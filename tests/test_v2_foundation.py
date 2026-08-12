from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from unittest.mock import patch

from mail_nuke.database import Database, SCHEMA_VERSION
from mail_nuke.indexer import parse_message, process_next_job, store_raw
from mail_nuke.preprocessing import load_group_profile, preprocess_email
from mail_nuke.reconciliation import reconcile_account
from mail_nuke.security import (
    SecretCipher,
    generate_session_token,
    hash_password,
    hash_session_token,
    session_expiry,
    verify_password,
)
from mail_nuke.training import build_samples, run_training, stable_split
from mail_nuke.scoring import ModelRuntime


class SecurityTests(unittest.TestCase):
    def test_password_hash_round_trip(self):
        encoded = hash_password("correct horse battery staple")
        self.assertNotIn("correct horse", encoded)
        self.assertTrue(verify_password("correct horse battery staple", encoded))
        self.assertFalse(verify_password("incorrect horse battery staple", encoded))

    def test_short_password_is_rejected(self):
        with self.assertRaises(ValueError):
            hash_password("too-short")

    def test_secret_cipher_persists_key_and_round_trips(self):
        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "secret.key"
            first = SecretCipher.load(None, key_path)
            encrypted = first.encrypt("imap-app-password")
            self.assertNotIn("imap-app-password", encrypted)
            second = SecretCipher.load(None, key_path)
            self.assertEqual(second.decrypt(encrypted), "imap-app-password")

    def test_privacy_pipeline_replaces_group_identity_and_known_secret(self):
        profile = {
            "version": 3,
            "account_emails": ["owner@example.com"],
            "custom_emails": ["alias@example.com"],
            "user_names": ["Taylor Example"],
            "known_secrets": ["old-password-123"],
            "normalize_other_emails": False,
        }
        raw = (
            b"From: Taylor Example <owner@example.com>\r\n"
            b"Subject: old-password-123 for alias@example.com\r\n\r\n"
            b"Hello Taylor Example, contact owner@example.com"
        )
        result = preprocess_email(raw, profile)
        self.assertNotIn("old-password-123", result["model_text"])
        self.assertNotIn("owner@example.com", result["model_text"])
        self.assertIn("__KNOWN_SECRET__", result["model_text"])
        self.assertIn("__GROUP_ACCOUNT_EMAIL__", result["model_text"])
        self.assertEqual(result["preprocessing_version"], 3)
        self.assertEqual(result["privacy_counts"]["known_secret"], 1)


class DatabaseTests(unittest.TestCase):
    def test_messages_are_sorted_by_actual_received_instant(self):
        with TemporaryDirectory() as directory:
            database = Database(Path(directory) / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": "encrypted-value",
                }
            )
            database.replace_discovered_folders(
                "account-id", [{"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": []}]
            )
            for message_id, subject, received_at, uid in (
                ("older", "Older instant", "2026-08-12T23:30:00+11:00", 1),
                ("newer", "Newer instant", "2026-08-12T13:00:00+00:00", 2),
            ):
                database.upsert_indexed_message(
                    {
                        "id": message_id, "account_id": "account-id", "message_key": message_id,
                        "rfc_message_id": f"<{message_id}@test>", "content_sha256": message_id,
                        "from_header": "sender@test", "sender_domain": "test", "subject": subject,
                        "received_at": received_at, "raw_storage_path": f"{message_id}.gz",
                        "effective_label": "ham", "label_source": "initial_folder:ham",
                    },
                    {"id": f"location-{message_id}", "folder_id": "inbox-id", "uid_validity": 1, "uid": uid},
                )

            messages = database.list_messages(account_id="account-id")["items"]
            self.assertEqual([message["id"] for message in messages], ["newer", "older"])

    def test_initializes_schema_and_allows_only_one_initial_admin(self):
        with TemporaryDirectory() as directory:
            database = Database(Path(directory) / "mail-nuke.db")
            database.initialize()
            self.assertFalse(database.is_configured())

            password_hash = hash_password("correct horse battery staple")
            database.create_initial_admin("admin-id", "admin", password_hash)
            self.assertTrue(database.is_configured())

            with self.assertRaises(RuntimeError):
                database.create_initial_admin("second-id", "second", password_hash)

            connection = sqlite3.connect(database.path)
            try:
                version = connection.execute(
                    "SELECT version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
                audit_count = connection.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE action = 'setup.admin_created'"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(version, SCHEMA_VERSION)
            self.assertEqual(audit_count, 1)

    def test_session_model_group_account_and_multiple_folder_roles(self):
        with TemporaryDirectory() as directory:
            database = Database(Path(directory) / "mail-nuke.db")
            database.initialize()
            password_hash = hash_password("correct horse battery staple")
            database.create_initial_admin("admin-id", "admin", password_hash)

            token = generate_session_token()
            token_hash = hash_session_token(token)
            database.create_session(token_hash, "admin-id", session_expiry())
            self.assertEqual(database.session_user(token_hash)["username"], "admin")

            database.create_model_group("group-id", "Shared personal")
            account = database.create_account(
                {
                    "id": "account-id",
                    "model_group_id": "group-id",
                    "display_name": "Example",
                    "email_address": "example@example.com",
                    "imap_host": "imap.example.com",
                    "imap_port": 993,
                    "imap_use_ssl": True,
                    "imap_username": "example@example.com",
                    "imap_password_ciphertext": "encrypted-value",
                }
            )
            self.assertNotIn("imap_password_ciphertext", account)

            database.replace_discovered_folders(
                "account-id",
                [
                    {"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": ["\\Inbox"]},
                    {"id": "junk-id", "path": "Junk", "delimiter": "/", "attributes": ["\\Junk"]},
                    {"id": "quarantine-id", "path": "Quarantine", "delimiter": "/", "attributes": []},
                ],
            )
            folders = database.set_folder_roles(
                "account-id",
                [
                    {"path": "INBOX", "role": "ham"},
                    {"path": "Junk", "role": "spam"},
                    {"path": "Quarantine", "role": "spam"},
                ],
            )
            roles = {folder["path"]: folder["role"] for folder in folders}
            self.assertEqual(roles, {"INBOX": "ham", "Junk": "spam", "Quarantine": "spam"})

            job = database.create_index_job("job-id", "account-id")
            self.assertEqual(job["status"], "queued")
            claimed = database.claim_index_job()
            self.assertEqual(claimed["id"], "job-id")
            self.assertEqual(claimed["status"], "running")
            self.assertEqual(database.recover_interrupted_jobs(), 1)
            self.assertEqual(database.get_job("job-id")["status"], "queued")
            database.claim_index_job()
            database.finish_job("job-id")
            self.assertEqual(database.get_job("job-id")["status"], "completed")

    def test_indexed_message_storage_and_counts(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_initial_admin(
                "admin-id", "admin", hash_password("correct horse battery staple")
            )
            database.create_model_group("group-id", "Personal")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": "encrypted-value",
                }
            )
            database.replace_discovered_folders(
                "account-id", [{"id": "junk-id", "path": "Junk", "delimiter": "/", "attributes": []}]
            )
            raw = b"Message-ID: <one@example.test>\r\nFrom: Sender <from@spam.test>\r\nSubject: Offer\r\n\r\nBody"
            parsed = parse_message(raw)
            stored = store_raw(root, parsed["content_sha256"], raw)
            parsed.update(
                {"id": "message-id", "account_id": "account-id", "raw_storage_path": stored,
                 "effective_label": "spam", "label_source": "initial_folder:spam"}
            )
            database.upsert_indexed_message(
                parsed,
                {"id": "location-id", "folder_id": "junk-id", "uid_validity": 7, "uid": 42},
            )
            counts = database.account_message_counts("account-id")
            self.assertEqual(counts, {"total": 1, "ham": 0, "spam": 1, "unlabelled": 0})
            self.assertTrue((root / stored).exists())
            self.assertEqual(parsed["sender_domain"], "spam.test")

            cipher = SecretCipher.load(None, root / "secret.key")
            database.update_privacy_profile(
                "group-id", [], [], False, cipher.encrypt('["Offer"]'), True
            )
            database.create_reprocess_job("privacy-job", "group-id")
            self.assertTrue(process_next_job(database, cipher, root))
            with database.connect() as connection:
                reprocessed = connection.execute(
                    "SELECT model_text, preprocessing_version FROM messages WHERE id = 'message-id'"
                ).fetchone()
            self.assertIn("__KNOWN_SECRET__", reprocessed["model_text"])
            self.assertNotIn("Offer", reprocessed["model_text"])
            self.assertEqual(reprocessed["preprocessing_version"], 2)

    def test_background_index_job_imports_selected_folder_and_checkpoints(self):
        class FakeImap:
            def __init__(self):
                self.fetch_fields = []

            def select_folder(self, path, readonly=True):
                self.selected = path
                return {b"UIDVALIDITY": 99}

            def search(self, criteria):
                return [7]

            def fetch(self, uids, fields):
                self.fetch_fields.append(fields)
                return {
                    7: {
                        b"BODY[]": b"Message-ID: <indexed@example.test>\r\nFrom: Bad <bad@noise.test>\r\nSubject: Noise\r\n\r\nBody"
                    }
                }

            def logout(self):
                return None

        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_initial_admin(
                "admin-id", "admin", hash_password("correct horse battery staple")
            )
            database.create_model_group("group-id", "Personal")
            cipher = SecretCipher.load(None, root / "secret.key")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": cipher.encrypt("app-password"),
                }
            )
            database.replace_discovered_folders(
                "account-id", [{"id": "junk-id", "path": "Junk", "delimiter": "/", "attributes": []}]
            )
            database.set_folder_roles("account-id", [{"path": "Junk", "role": "spam"}])
            database.create_index_job("job-id", "account-id")

            client = FakeImap()
            with patch("mail_nuke.indexer.connect", return_value=client):
                self.assertTrue(process_next_job(database, cipher, root))

            self.assertEqual(client.fetch_fields, [["BODY.PEEK[]"]])
            self.assertEqual(database.get_job("job-id")["status"], "completed")
            self.assertEqual(database.account_message_counts("account-id")["spam"], 1)
            folder = database.list_folders("account-id")[0]
            self.assertEqual(folder["uid_validity"], 99)
            self.assertEqual(folder["last_indexed_uid"], 7)
            self.assertEqual(folder["index_status"], "completed")

            with database.connect() as connection:
                indexed = connection.execute(
                    "SELECT model_text, preprocessing_version FROM messages"
                ).fetchone()
            self.assertIn("from_domain=noise.test", indexed["model_text"])
            self.assertEqual(indexed["preprocessing_version"], 1)

    def test_privacy_profile_update_is_versioned_and_queues_reprocessing(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            cipher = SecretCipher.load(None, root / "secret.key")
            encrypted = cipher.encrypt('["sensitive-value"]')
            updated = database.update_privacy_profile(
                "group-id", ["Taylor Example"], ["alias@example.com"], False,
                encrypted, True,
            )
            self.assertEqual(updated["version"], 2)
            profile = load_group_profile(database, cipher, "group-id")
            self.assertEqual(profile["known_secrets"], ["sensitive-value"])
            job = database.create_reprocess_job("reprocess-id", "group-id")
            self.assertEqual(job["kind"], "reprocess_privacy")
            self.assertEqual(job["status"], "queued")

    def test_reconciliation_move_correction_deletion_and_dashboard_override(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": "encrypted-value",
                }
            )
            database.replace_discovered_folders(
                "account-id",
                [
                    {"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": []},
                    {"id": "junk-id", "path": "Junk", "delimiter": "/", "attributes": []},
                ],
            )
            database.set_folder_roles(
                "account-id", [{"path": "INBOX", "role": "ham"}, {"path": "Junk", "role": "spam"}]
            )
            raw = b"Message-ID: <move@test>\r\nFrom: sender@noise.test\r\nSubject: Move me\r\n\r\nBody"
            parsed = parse_message(raw)
            parsed.update(
                {"id": "message-id", "account_id": "account-id",
                 "raw_storage_path": store_raw(root, parsed["content_sha256"], raw),
                 "effective_label": "spam", "label_source": "initial_folder:spam"}
            )
            database.upsert_indexed_message(
                parsed, {"id": "junk-location", "folder_id": "junk-id", "uid_validity": 1, "uid": 10}
            )

            corrected = dict(parsed, id="duplicate-id", effective_label="ham", label_source="folder_reconciliation:ham")
            database.upsert_indexed_message(
                corrected, {"id": "inbox-location", "folder_id": "inbox-id", "uid_validity": 2, "uid": 20}
            )
            database.finalize_reconciliation("account-id", {("inbox-id", 2, 20)})
            reviewed = database.list_messages(account_id="account-id")["items"][0]
            self.assertEqual(reviewed["effective_label"], "ham")
            self.assertEqual(reviewed["mailbox_status"], "present")
            self.assertTrue(any(event["event_type"] == "folder_move" for event in database.message_events("message-id")))

            database.finalize_reconciliation("account-id", set())
            deleted = database.list_messages(account_id="account-id")["items"][0]
            self.assertEqual(deleted["mailbox_status"], "deleted")
            self.assertEqual(deleted["effective_label"], "ham")
            self.assertEqual(deleted["training_status"], "included")

            database.update_message_review("message-id", label="spam", training_status="excluded")
            database.finalize_reconciliation("account-id", {("inbox-id", 2, 20)})
            overridden = database.list_messages(account_id="account-id")["items"][0]
            self.assertEqual(overridden["effective_label"], "spam")
            self.assertEqual(overridden["label_source"], "dashboard")
            self.assertEqual(overridden["training_status"], "excluded")

    def test_partial_reconciliation_failure_does_not_mark_messages_deleted(self):
        class PartialFailureImap:
            def select_folder(self, path, readonly=True):
                if path == "Junk":
                    raise RuntimeError("temporary server failure")
                return {b"UIDVALIDITY": 2}

            def search(self, criteria):
                return []

            def logout(self):
                return None

        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            cipher = SecretCipher.load(None, root / "secret.key")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": cipher.encrypt("app-password"),
                }
            )
            database.replace_discovered_folders(
                "account-id",
                [
                    {"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": []},
                    {"id": "junk-id", "path": "Junk", "delimiter": "/", "attributes": []},
                ],
            )
            database.set_folder_roles(
                "account-id", [{"path": "INBOX", "role": "ham"}, {"path": "Junk", "role": "spam"}]
            )
            raw = b"Message-ID: <safe@test>\r\nFrom: sender@noise.test\r\nSubject: Safe\r\n\r\nBody"
            parsed = parse_message(raw)
            parsed.update(
                {"id": "message-id", "account_id": "account-id",
                 "raw_storage_path": store_raw(root, parsed["content_sha256"], raw),
                 "effective_label": "spam", "label_source": "initial_folder:spam"}
            )
            database.upsert_indexed_message(
                parsed, {"id": "junk-location", "folder_id": "junk-id", "uid_validity": 1, "uid": 10}
            )
            job = {"id": "reconcile-id", "account_id": "account-id"}
            with patch("mail_nuke.reconciliation.connect", return_value=PartialFailureImap()):
                with self.assertRaises(RuntimeError):
                    reconcile_account(database, cipher, root, job)
            message = database.list_messages(account_id="account-id")["items"][0]
            self.assertEqual(message["mailbox_status"], "present")
            self.assertEqual(message["effective_label"], "spam")

    def test_reconciliation_scores_and_moves_new_monitored_spam(self):
        class FakeRuntime:
            def score(self, database, group_id, model_text, preprocessing_version):
                return {
                    "model_group_id": group_id, "model_version_id": "model-id",
                    "score": 0.98, "threshold": 0.9, "label": "spam",
                }

        class FakeImap:
            def __init__(self):
                self.selected = None
                self.moves = []
                self.flags = []
                self.fetch_fields = []

            def select_folder(self, path, readonly=True):
                self.selected = path
                return {b"UIDVALIDITY": 1}

            def search(self, criteria):
                return [7] if self.selected == "INBOX" else []

            def fetch(self, uids, fields):
                self.fetch_fields.append(fields)
                return {7: {b"BODY[]": b"Message-ID: <live@test>\r\nFrom: Bad <bad@noise.test>\r\nSubject: Prize\r\n\r\nClaim now"}}

            def add_flags(self, uids, flags):
                self.flags.append((uids, flags))

            def move(self, uids, destination):
                self.moves.append((uids, destination))

            def logout(self):
                return None

        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            cipher = SecretCipher.load(None, root / "secret.key")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": cipher.encrypt("app-password"),
                }
            )
            database.replace_discovered_folders(
                "account-id",
                [
                    {"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": []},
                    {"id": "junk-id", "path": "Junk", "delimiter": "/", "attributes": []},
                ],
            )
            database.set_folder_roles(
                "account-id", [{"path": "INBOX", "role": "ham"}, {"path": "Junk", "role": "spam"}]
            )
            with database.connect() as connection:
                connection.execute(
                    "UPDATE accounts SET automation_mode = 'move', spam_destination_folder_id = 'junk-id' WHERE id = 'account-id'"
                )
                connection.execute(
                    """INSERT INTO dataset_generations(
                           id, model_group_id, privacy_profile_version, status, created_at
                       ) VALUES ('dataset-id', 'group-id', 1, 'ready', '2026-01-01')"""
                )
                connection.execute(
                    """INSERT INTO model_versions(
                           id, model_group_id, dataset_generation_id, artifact_path,
                           recommended_threshold, metrics_json, status, created_at
                       ) VALUES ('model-id', 'group-id', 'dataset-id', 'unused', 0.9, '{}', 'active', '2026-01-01')"""
                )
                connection.commit()
            client = FakeImap()
            with patch("mail_nuke.reconciliation.connect", return_value=client):
                reconcile_account(
                    database, cipher, root, {"id": "reconcile-id", "account_id": "account-id"}, FakeRuntime()
                )
            self.assertEqual(client.moves, [([7], "Junk")])
            self.assertEqual(client.fetch_fields, [["BODY.PEEK[]"]])
            self.assertEqual(client.flags, [([7], [r"\Seen"])])
            message = database.list_messages(search="Prize")["items"][0]
            self.assertEqual(message["prediction_action_status"], "moved")
            self.assertIsNone(message["effective_label"])
            self.assertEqual(message["label_source"], "automated_move")

    def test_group_training_creates_active_model_and_threshold_override_is_pinned(self):
        def digest_for(split, start):
            value = start
            while stable_split(f"digest-{value}", "initial_folder") != split:
                value += 1
            return f"digest-{value}", value + 1

        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": "encrypted-value",
                }
            )
            database.replace_discovered_folders(
                "account-id", [
                    {"id": "folder-id", "path": "Archive", "delimiter": "/", "attributes": []},
                    {"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": []},
                ]
            )
            database.set_folder_roles(
                "account-id",
                [{"path": "Archive", "role": "spam"}, {"path": "INBOX", "role": "monitored"}],
            )
            cursor = 0
            uid = 1
            desired = [("train", "ham"), ("train", "ham"), ("train", "spam"), ("train", "spam"),
                       ("valid", "ham"), ("valid", "spam"), ("test", "ham"), ("test", "spam")]
            for split, label in desired:
                digest, cursor = digest_for(split, cursor)
                database.upsert_indexed_message(
                    {
                        "id": f"message-{uid}", "account_id": "account-id", "message_key": f"key-{uid}",
                        "rfc_message_id": f"<message-{uid}@test>", "content_sha256": digest,
                        "from_header": f"sender{uid}@test", "sender_domain": "test",
                        "subject": f"{label} sample", "received_at": None,
                        "raw_storage_path": f"raw-{uid}.gz", "effective_label": label,
                        "label_source": "initial_folder", "model_text": (
                            "from_domain=test\nsubject=ordinary meeting project" if label == "ham"
                            else "from_domain=noise.test\nsubject=urgent prize offer"
                        ),
                        "preprocessing_version": 1, "privacy_counts": {},
                    },
                    {"id": f"location-{uid}", "folder_id": "folder-id", "uid_validity": 1, "uid": uid},
                )
                uid += 1
            self.assertEqual(database.queue_due_training(604800), 1)
            queued = database.model_group_status("group-id")["jobs"][0]
            with database.connect() as connection:
                connection.execute(
                    "UPDATE jobs SET context_json = ? WHERE id = ?",
                    ('{"group_id":"group-id"}', queued["id"]),
                )
                connection.commit()
            self.assertEqual(database.queue_due_training(604800), 0)
            self.assertEqual(database.model_group_status("group-id")["jobs"][0]["id"], queued["id"])
            job = {"id": "training-job", "context_json": '{"group_id": "group-id"}'}
            result = run_training(database, root, job)
            self.assertTrue(result["promoted"])
            active = database.active_model_version("group-id")
            self.assertEqual(active["id"], result["version_id"])
            self.assertTrue((root / active["artifact_path"]).exists())
            status = database.set_threshold_override("group-id", 0.77)
            self.assertEqual(status["effective_threshold"], 0.77)
            self.assertEqual(status["group"]["threshold_override"], 0.77)
            account = database.set_account_automation("account-id", "observe", "folder-id")
            self.assertEqual(account["automation_mode"], "observe")
            runtime = ModelRuntime(root)
            prediction = runtime.score(
                database, "group-id", "from_domain=noise.test\nsubject=urgent prize offer", 1
            )
            self.assertEqual(prediction["model_version_id"], active["id"])
            self.assertGreaterEqual(prediction["score"], 0)
            self.assertLessEqual(prediction["score"], 1)
            with self.assertRaises(RuntimeError):
                runtime.score(database, "group-id", "anything", 2)
            stored = database.create_prediction(
                {
                    "id": "prediction-id", "message_id": "message-1", **prediction,
                    "action_mode": "observe", "action_status": "dry_run",
                    "source_folder_id": "inbox-id", "source_uid_validity": 1,
                    "source_uid": 101, "destination_folder_id": "folder-id",
                }
            )
            self.assertEqual(stored["action_status"], "dry_run")
            self.assertEqual(database.latest_prediction("message-1")["id"], "prediction-id")
            database.upsert_indexed_message(
                {
                    "id": "auto-message", "account_id": "account-id", "message_key": "auto-key",
                    "rfc_message_id": "<auto@test>", "content_sha256": "auto-digest",
                    "from_header": "sender@noise.test", "sender_domain": "noise.test",
                    "subject": "automated candidate", "received_at": None,
                    "raw_storage_path": "auto.gz", "effective_label": None,
                    "label_source": None, "model_text": "urgent prize offer",
                    "preprocessing_version": 1, "privacy_counts": {},
                },
                {"id": "auto-inbox", "folder_id": "inbox-id", "uid_validity": 1, "uid": 200},
            )
            moved_prediction = database.create_prediction(
                {
                    "id": "moved-prediction", "message_id": "auto-message", **prediction,
                    "label": "spam", "action_mode": "move", "action_status": "pending",
                    "source_folder_id": "inbox-id", "source_uid_validity": 1,
                    "source_uid": 200, "destination_folder_id": "folder-id",
                }
            )
            database.finish_prediction_action(moved_prediction["id"], "moved")
            database.upsert_indexed_message(
                {
                    "id": "ignored", "account_id": "account-id", "message_key": "auto-key",
                    "rfc_message_id": "<auto@test>", "content_sha256": "auto-digest",
                    "from_header": "sender@noise.test", "sender_domain": "noise.test",
                    "subject": "automated candidate", "received_at": None,
                    "raw_storage_path": "auto.gz", "effective_label": "spam",
                    "label_source": "folder_reconciliation:spam", "model_text": "urgent prize offer",
                    "preprocessing_version": 1, "privacy_counts": {},
                },
                {"id": "auto-spam", "folder_id": "folder-id", "uid_validity": 1, "uid": 201},
            )
            database.finalize_reconciliation("account-id", {("folder-id", 1, 201)})
            automated = database.list_messages(search="automated candidate")["items"][0]
            self.assertIsNone(automated["effective_label"])
            self.assertEqual(automated["label_source"], "automated_move")
            database.create_index_job("readiness-index", "account-id")
            database.finish_job("readiness-index")
            database.set_account_automation("account-id", "move", "folder-id")
            readiness = database.deployment_readiness()
            self.assertTrue(readiness["ready"])
            self.assertEqual(readiness["accounts"][0]["status"], "active")
            self.assertTrue(readiness["accounts"][0]["ready_to_observe"])

    def test_mailbox_jobs_wait_for_folder_setup_and_initial_index(self):
        with TemporaryDirectory() as directory:
            database = Database(Path(directory) / "mail-nuke.db")
            database.initialize()
            database.create_model_group("group-id", "Personal")
            database.create_account(
                {
                    "id": "account-id", "model_group_id": "group-id", "display_name": "Example",
                    "email_address": "example@example.com", "imap_host": "imap.example.com",
                    "imap_port": 993, "imap_use_ssl": True, "imap_username": "example@example.com",
                    "imap_password_ciphertext": "encrypted-value",
                }
            )

            with self.assertRaisesRegex(RuntimeError, "assign at least one"):
                database.create_index_job("early-index", "account-id")
            with self.assertRaisesRegex(RuntimeError, "folder roles"):
                database.create_reconcile_job("early-sync", "account-id")
            self.assertEqual(database.queue_due_reconciliations(0), 0)

            database.replace_discovered_folders(
                "account-id", [{"id": "inbox-id", "path": "INBOX", "delimiter": "/", "attributes": []}]
            )
            database.set_folder_roles("account-id", [{"path": "INBOX", "role": "monitored"}])
            database.create_index_job("initial-index", "account-id")
            with self.assertRaisesRegex(RuntimeError, "initial mailbox index"):
                database.create_reconcile_job("pre-index-sync", "account-id")
            self.assertEqual(database.queue_due_reconciliations(0), 0)

            database.finish_job("initial-index")
            self.assertEqual(database.queue_due_reconciliations(0), 1)


    def test_dataset_deduplication_excludes_conflicting_labels(self):
        rows = [
            {"id": "a", "content_sha256": "same", "effective_label": "ham", "label_source": "folder"},
            {"id": "b", "content_sha256": "same", "effective_label": "spam", "label_source": "dashboard"},
            {"id": "c", "content_sha256": "duplicate", "effective_label": "spam", "label_source": "folder"},
            {"id": "d", "content_sha256": "duplicate", "effective_label": "spam", "label_source": "folder"},
        ]
        samples, deduplicated, ambiguous = build_samples(rows)
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["message_id"], "c")
        self.assertEqual(deduplicated, 1)
        self.assertEqual(ambiguous, 2)


if __name__ == "__main__":
    unittest.main()
