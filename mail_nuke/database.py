from __future__ import annotations

import sqlite3
import json
import re
from datetime import timedelta
from contextlib import contextmanager
from contextlib import nullcontext
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 8


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_user_id TEXT REFERENCES users(id),
                    action TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    outcome TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    error_summary TEXT
                );
                """
            )
            row = connection.execute(
                "SELECT version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO schema_metadata(singleton, version) VALUES (1, ?)",
                    (1,),
                )
                current_version = 1
            else:
                current_version = int(row["version"])
            if current_version == 1:
                self._migrate_v1_to_v2(connection)
                current_version = 2
            if current_version == 2:
                self._migrate_v2_to_v3(connection)
                current_version = 3
            if current_version == 3:
                self._migrate_v3_to_v4(connection)
                current_version = 4
            if current_version == 4:
                self._migrate_v4_to_v5(connection)
                current_version = 5
            if current_version == 5:
                self._migrate_v5_to_v6(connection)
                current_version = 6
            if current_version == 6:
                self._migrate_v6_to_v7(connection)
                current_version = 7
            if current_version == 7:
                self._migrate_v7_to_v8(connection)
                current_version = 8
            if current_version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"Unsupported database schema {current_version}; expected {SCHEMA_VERSION}"
                )
            connection.commit()

    def recover_interrupted_jobs(self) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs SET status = 'queued', started_at = NULL,
                    error_summary = CASE
                        WHEN kind = 'reprocess_privacy' THEN error_summary
                        ELSE 'Recovered after application restart'
                    END
                WHERE status = 'running'
                """
            )
            connection.commit()
            return int(cursor.rowcount)

    def _migrate_v1_to_v2(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            );

            CREATE TABLE model_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                threshold_override REAL CHECK (
                    threshold_override IS NULL OR
                    (threshold_override >= 0 AND threshold_override <= 1)
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                model_group_id TEXT NOT NULL REFERENCES model_groups(id),
                display_name TEXT NOT NULL,
                email_address TEXT NOT NULL,
                imap_host TEXT NOT NULL,
                imap_port INTEGER NOT NULL CHECK (imap_port > 0 AND imap_port <= 65535),
                imap_use_ssl INTEGER NOT NULL CHECK (imap_use_ssl IN (0, 1)),
                imap_username TEXT NOT NULL,
                imap_password_ciphertext TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE folders (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                delimiter TEXT,
                attributes_json TEXT NOT NULL DEFAULT '[]',
                role TEXT NOT NULL DEFAULT 'neutral' CHECK (
                    role IN ('spam', 'ham', 'monitored', 'excluded', 'neutral')
                ),
                discovered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(account_id, path)
            );

            CREATE INDEX idx_accounts_model_group ON accounts(model_group_id);
            CREATE INDEX idx_folders_account_role ON folders(account_id, role);
            UPDATE schema_metadata SET version = 2 WHERE singleton = 1;
            """
        )

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            ALTER TABLE folders ADD COLUMN uid_validity INTEGER;
            ALTER TABLE folders ADD COLUMN last_indexed_uid INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE folders ADD COLUMN index_status TEXT NOT NULL DEFAULT 'not_started';
            ALTER TABLE folders ADD COLUMN index_error TEXT;

            ALTER TABLE jobs ADD COLUMN account_id TEXT REFERENCES accounts(id);
            ALTER TABLE jobs ADD COLUMN progress_current INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE jobs ADD COLUMN progress_total INTEGER;

            CREATE TABLE messages (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                message_key TEXT NOT NULL,
                rfc_message_id TEXT,
                content_sha256 TEXT NOT NULL,
                from_header TEXT NOT NULL DEFAULT '',
                sender_domain TEXT,
                subject TEXT NOT NULL DEFAULT '',
                received_at TEXT,
                raw_storage_path TEXT NOT NULL,
                mailbox_status TEXT NOT NULL DEFAULT 'present' CHECK (
                    mailbox_status IN ('present', 'moved', 'deleted', 'unavailable')
                ),
                training_status TEXT NOT NULL DEFAULT 'included' CHECK (
                    training_status IN ('included', 'excluded', 'purged')
                ),
                effective_label TEXT CHECK (effective_label IN ('ham', 'spam') OR effective_label IS NULL),
                label_source TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(account_id, message_key)
            );

            CREATE TABLE message_locations (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                uid_validity INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                present INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0, 1)),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(folder_id, uid_validity, uid)
            );

            CREATE INDEX idx_messages_account_label ON messages(account_id, effective_label);
            CREATE INDEX idx_messages_content_sha256 ON messages(content_sha256);
            CREATE INDEX idx_message_locations_message_present ON message_locations(message_id, present);
            CREATE INDEX idx_jobs_status_created ON jobs(status, created_at);
            UPDATE schema_metadata SET version = 3 WHERE singleton = 1;
            PRAGMA optimize;
            """
        )

    def _migrate_v3_to_v4(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE privacy_profiles (
                id TEXT PRIMARY KEY,
                model_group_id TEXT NOT NULL UNIQUE REFERENCES model_groups(id) ON DELETE CASCADE,
                version INTEGER NOT NULL DEFAULT 1,
                user_names_json TEXT NOT NULL DEFAULT '[]',
                custom_emails_json TEXT NOT NULL DEFAULT '[]',
                known_secrets_ciphertext TEXT,
                normalize_other_emails INTEGER NOT NULL DEFAULT 0 CHECK (normalize_other_emails IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            INSERT INTO privacy_profiles(id, model_group_id, version, created_at, updated_at)
            SELECT lower(hex(randomblob(16))), id, 1, created_at, updated_at FROM model_groups;

            ALTER TABLE messages ADD COLUMN model_text TEXT;
            ALTER TABLE messages ADD COLUMN preprocessing_version INTEGER;
            ALTER TABLE messages ADD COLUMN privacy_counts_json TEXT NOT NULL DEFAULT '{}';
            ALTER TABLE messages ADD COLUMN processed_at TEXT;
            ALTER TABLE jobs ADD COLUMN context_json TEXT NOT NULL DEFAULT '{}';

            CREATE INDEX idx_messages_group_reprocessing
            ON messages(account_id, preprocessing_version);
            UPDATE schema_metadata SET version = 4 WHERE singleton = 1;
            PRAGMA optimize;
            """
        )

    def _migrate_v4_to_v5(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            ALTER TABLE messages ADD COLUMN deleted_detected_at TEXT;
            ALTER TABLE messages ADD COLUMN training_status_changed_at TEXT;
            ALTER TABLE messages ADD COLUMN label_changed_at TEXT;
            ALTER TABLE folders ADD COLUMN last_reconciled_at TEXT;

            CREATE TABLE message_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX idx_message_events_message_created
            ON message_events(message_id, created_at DESC);
            CREATE INDEX idx_messages_review
            ON messages(mailbox_status, training_status, effective_label, last_seen_at DESC);
            UPDATE schema_metadata SET version = 5 WHERE singleton = 1;
            PRAGMA optimize;
            """
        )

    def _migrate_v5_to_v6(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            ALTER TABLE model_groups ADD COLUMN active_model_version_id TEXT;

            CREATE TABLE dataset_generations (
                id TEXT PRIMARY KEY,
                model_group_id TEXT NOT NULL REFERENCES model_groups(id) ON DELETE CASCADE,
                privacy_profile_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                total_samples INTEGER NOT NULL DEFAULT 0,
                ham_samples INTEGER NOT NULL DEFAULT 0,
                spam_samples INTEGER NOT NULL DEFAULT 0,
                deduplicated_samples INTEGER NOT NULL DEFAULT 0,
                ambiguous_samples INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE training_samples (
                dataset_generation_id TEXT NOT NULL REFERENCES dataset_generations(id) ON DELETE CASCADE,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                label TEXT NOT NULL CHECK (label IN ('ham', 'spam')),
                split TEXT NOT NULL CHECK (split IN ('train', 'valid', 'test')),
                content_sha256 TEXT NOT NULL,
                PRIMARY KEY(dataset_generation_id, message_id)
            );

            CREATE TABLE model_versions (
                id TEXT PRIMARY KEY,
                model_group_id TEXT NOT NULL REFERENCES model_groups(id) ON DELETE CASCADE,
                dataset_generation_id TEXT NOT NULL REFERENCES dataset_generations(id),
                artifact_path TEXT NOT NULL,
                recommended_threshold REAL NOT NULL,
                metrics_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('candidate', 'active', 'rejected', 'superseded')),
                created_at TEXT NOT NULL,
                activated_at TEXT
            );

            CREATE INDEX idx_dataset_generations_group_created
            ON dataset_generations(model_group_id, created_at DESC);
            CREATE INDEX idx_training_samples_generation_split
            ON training_samples(dataset_generation_id, split, label);
            CREATE INDEX idx_model_versions_group_created
            ON model_versions(model_group_id, created_at DESC);
            UPDATE schema_metadata SET version = 6 WHERE singleton = 1;
            PRAGMA optimize;
            """
        )

    def _migrate_v6_to_v7(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            ALTER TABLE accounts ADD COLUMN automation_mode TEXT NOT NULL DEFAULT 'off'
                CHECK (automation_mode IN ('off', 'observe', 'move'));
            ALTER TABLE accounts ADD COLUMN spam_destination_folder_id TEXT REFERENCES folders(id);

            CREATE TABLE predictions (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                model_group_id TEXT NOT NULL REFERENCES model_groups(id) ON DELETE CASCADE,
                model_version_id TEXT NOT NULL REFERENCES model_versions(id),
                score REAL NOT NULL CHECK (score >= 0 AND score <= 1),
                threshold REAL NOT NULL CHECK (threshold >= 0 AND threshold <= 1),
                label TEXT NOT NULL CHECK (label IN ('ham', 'spam')),
                action_mode TEXT NOT NULL CHECK (action_mode IN ('off', 'observe', 'move')),
                action_status TEXT NOT NULL CHECK (
                    action_status IN ('not_requested', 'dry_run', 'pending', 'moved', 'failed')
                ),
                source_folder_id TEXT REFERENCES folders(id),
                source_uid_validity INTEGER,
                source_uid INTEGER,
                destination_folder_id TEXT REFERENCES folders(id),
                error_summary TEXT,
                created_at TEXT NOT NULL,
                actioned_at TEXT
            );

            CREATE INDEX idx_predictions_message_created
            ON predictions(message_id, created_at DESC);
            CREATE INDEX idx_predictions_group_created
            ON predictions(model_group_id, created_at DESC);
            UPDATE schema_metadata SET version = 7 WHERE singleton = 1;
            PRAGMA optimize;
            """
        )

    def _migrate_v7_to_v8(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE VIRTUAL TABLE messages_search USING fts5(
                subject, from_header, sender_domain
            );
            INSERT INTO messages_search(rowid, subject, from_header, sender_domain)
            SELECT rowid, subject, from_header, sender_domain FROM messages;

            CREATE TRIGGER messages_search_insert AFTER INSERT ON messages BEGIN
                INSERT INTO messages_search(rowid, subject, from_header, sender_domain)
                VALUES (new.rowid, new.subject, new.from_header, new.sender_domain);
            END;
            CREATE TRIGGER messages_search_delete AFTER DELETE ON messages BEGIN
                DELETE FROM messages_search WHERE rowid = old.rowid;
            END;
            CREATE TRIGGER messages_search_update
            AFTER UPDATE OF subject, from_header, sender_domain ON messages BEGIN
                DELETE FROM messages_search WHERE rowid = old.rowid;
                INSERT INTO messages_search(rowid, subject, from_header, sender_domain)
                VALUES (new.rowid, new.subject, new.from_header, new.sender_domain);
            END;
            UPDATE schema_metadata SET version = 8 WHERE singleton = 1;
            PRAGMA optimize;
            """
        )

    def is_configured(self) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE enabled = 1"
            ).fetchone()
            return bool(row and row["count"])

    def create_initial_admin(self, user_id: str, username: str, password_hash: str) -> None:
        username = username.strip()
        if not username:
            raise ValueError("Administrator username is required")
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if existing:
                raise RuntimeError("Mail Nuke has already been configured")
            connection.execute(
                """
                INSERT INTO users(id, username, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, username, password_hash, now, now),
            )
            connection.execute(
                """
                INSERT INTO audit_events(
                    actor_user_id, action, target_type, target_id, outcome, created_at
                ) VALUES (?, 'setup.admin_created', 'user', ?, 'success', ?)
                """,
                (user_id, user_id, now),
            )
            connection.commit()

    def find_user_by_username(self, username: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM users WHERE username = ? AND enabled = 1",
                (username.strip(),),
            ).fetchone()

    def create_session(self, token_hash: str, user_id: str, expires_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, user_id, utc_now(), expires_at),
            )
            connection.commit()

    def session_user(self, token_hash: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT users.* FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ?
                  AND sessions.revoked_at IS NULL
                  AND sessions.expires_at > ?
                  AND users.enabled = 1
                """,
                (token_hash, utc_now()),
            ).fetchone()

    def revoke_session(self, token_hash: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
                (utc_now(), token_hash),
            )
            connection.commit()

    def create_model_group(self, group_id: str, name: str) -> dict:
        name = name.strip()
        if not name:
            raise ValueError("Model group name is required")
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO model_groups(id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (group_id, name, now, now),
            )
            connection.execute(
                """
                INSERT INTO privacy_profiles(id, model_group_id, version, created_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
                """,
                (f"privacy-{group_id}", group_id, now, now),
            )
            connection.commit()
        return {"id": group_id, "name": name, "threshold_override": None}

    def list_model_groups(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT model_groups.*, COUNT(accounts.id) AS account_count
                FROM model_groups
                LEFT JOIN accounts ON accounts.model_group_id = model_groups.id
                GROUP BY model_groups.id
                ORDER BY model_groups.name COLLATE NOCASE
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def get_model_group(self, group_id: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM model_groups WHERE id = ?", (group_id,)
            ).fetchone()

    def create_account(self, values: dict) -> dict:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO accounts(
                    id, model_group_id, display_name, email_address, imap_host,
                    imap_port, imap_use_ssl, imap_username, imap_password_ciphertext,
                    enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    values["id"], values["model_group_id"], values["display_name"],
                    values["email_address"], values["imap_host"], values["imap_port"],
                    int(values["imap_use_ssl"]), values["imap_username"],
                    values["imap_password_ciphertext"], now, now,
                ),
            )
            connection.commit()
        return self.public_account(values["id"])

    def public_account(self, account_id: str) -> dict:
        row = self.get_account(account_id)
        if row is None:
            raise KeyError(account_id)
        result = dict(row)
        result.pop("imap_password_ciphertext", None)
        result["imap_use_ssl"] = bool(result["imap_use_ssl"])
        return result

    def get_account(self, account_id: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()

    def list_accounts(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id FROM accounts ORDER BY display_name COLLATE NOCASE"
            ).fetchall()
        return [self.public_account(row["id"]) for row in rows]

    def replace_discovered_folders(self, account_id: str, folders: list[dict]) -> list[dict]:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for folder in folders:
                connection.execute(
                    """
                    INSERT INTO folders(
                        id, account_id, path, delimiter, attributes_json,
                        role, discovered_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'neutral', ?, ?)
                    ON CONFLICT(account_id, path) DO UPDATE SET
                        delimiter = excluded.delimiter,
                        attributes_json = excluded.attributes_json,
                        discovered_at = excluded.discovered_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        folder["id"], account_id, folder["path"], folder.get("delimiter"),
                        json.dumps(folder.get("attributes", [])), now, now,
                    ),
                )
            connection.commit()
        return self.list_folders(account_id)

    def list_folders(self, account_id: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM folders WHERE account_id = ? ORDER BY path COLLATE NOCASE",
                (account_id,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["attributes"] = json.loads(item.pop("attributes_json"))
            result.append(item)
        return result

    def set_folder_roles(self, account_id: str, assignments: list[dict]) -> list[dict]:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            known = {
                row["path"]
                for row in connection.execute(
                    "SELECT path FROM folders WHERE account_id = ?", (account_id,)
                ).fetchall()
            }
            requested = {item["path"] for item in assignments}
            unknown = requested - known
            if unknown:
                raise ValueError(f"Folders have not been discovered: {', '.join(sorted(unknown))}")
            for item in assignments:
                connection.execute(
                    "UPDATE folders SET role = ?, updated_at = ? WHERE account_id = ? AND path = ?",
                    (item["role"], now, account_id, item["path"]),
                )
            connection.commit()
        return self.list_folders(account_id)

    def set_account_automation(
        self, account_id: str, mode: str, spam_destination_folder_id: str | None
    ) -> dict:
        if mode not in {"off", "observe", "move"}:
            raise ValueError("Automation mode must be off, observe, or move")
        with self.connect() as connection:
            account = connection.execute(
                "SELECT * FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if account is None:
                raise KeyError(account_id)
            destination = None
            if spam_destination_folder_id:
                destination = connection.execute(
                    "SELECT * FROM folders WHERE id = ? AND account_id = ? AND role = 'spam'",
                    (spam_destination_folder_id, account_id),
                ).fetchone()
                if destination is None:
                    raise ValueError("The destination must be a configured Spam folder for this account")
            if mode == "move" and destination is None:
                raise ValueError("Move mode requires a Spam destination folder")
            if mode != "off":
                model = connection.execute(
                    """SELECT model_versions.id FROM model_groups
                       JOIN model_versions ON model_versions.id = model_groups.active_model_version_id
                       WHERE model_groups.id = ?""",
                    (account["model_group_id"],),
                ).fetchone()
                if model is None:
                    raise ValueError("Train and activate a model before enabling automation")
            connection.execute(
                """UPDATE accounts
                   SET automation_mode = ?, spam_destination_folder_id = ?, updated_at = ?
                   WHERE id = ?""",
                (mode, destination["id"] if destination else None, utc_now(), account_id),
            )
            connection.commit()
        return self.public_account(account_id)

    def create_index_job(self, job_id: str, account_id: str) -> dict:
        if self.get_account(account_id) is None:
            raise KeyError(account_id)
        if not self.indexable_folders(account_id):
            raise RuntimeError(
                "Discover folders and assign at least one Ham, Spam, or Monitored role before indexing"
            )
        now = utc_now()
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT id FROM jobs WHERE account_id = ? AND kind = 'initial_index' AND status IN ('queued', 'running')",
                (account_id,),
            ).fetchone()
            if existing:
                raise RuntimeError("An indexing job is already queued or running for this account")
            connection.execute(
                "INSERT INTO jobs(id, kind, status, account_id, created_at) VALUES (?, 'initial_index', 'queued', ?, ?)",
                (job_id, account_id, now),
            )
            connection.commit()
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return dict(row) if row else None

    def list_jobs(self, account_id: str | None = None) -> list[dict]:
        with self.connect() as connection:
            if account_id:
                rows = connection.execute(
                    "SELECT * FROM jobs WHERE account_id = ? ORDER BY created_at DESC", (account_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 100").fetchall()
            return [dict(row) for row in rows]

    def claim_index_job(self) -> dict | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM jobs WHERE kind = 'initial_index' AND status = 'queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            connection.execute(
                "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?",
                (utc_now(), row["id"]),
            )
            connection.commit()
            return self.get_job(row["id"])

    def update_job_progress(self, job_id: str, current: int, total: int | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET progress_current = ?, progress_total = COALESCE(?, progress_total) WHERE id = ?",
                (current, total, job_id),
            )
            connection.commit()

    def finish_job(self, job_id: str, error: str | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET status = ?, finished_at = ?, error_summary = ? WHERE id = ?",
                ("failed" if error else "completed", utc_now(), error, job_id),
            )
            connection.commit()

    def indexable_folders(self, account_id: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM folders WHERE account_id = ? AND role IN ('ham', 'spam', 'monitored') ORDER BY path",
                (account_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def reset_folder_checkpoint(self, folder_id: str, uid_validity: int) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE folders SET uid_validity = ?, last_indexed_uid = 0, index_status = 'running', index_error = NULL WHERE id = ?",
                (uid_validity, folder_id),
            )
            connection.commit()

    def update_folder_checkpoint(self, folder_id: str, uid: int, status: str = "running") -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE folders SET last_indexed_uid = MAX(last_indexed_uid, ?), index_status = ?, index_error = NULL WHERE id = ?",
                (uid, status, folder_id),
            )
            connection.commit()

    def fail_folder_index(self, folder_id: str, error: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE folders SET index_status = 'failed', index_error = ? WHERE id = ?",
                (error[:500], folder_id),
            )
            connection.commit()

    def upsert_indexed_message(
        self, message: dict, location: dict, existing_connection: sqlite3.Connection | None = None
    ) -> str:
        now = utc_now()
        manager = self.connect() if existing_connection is None else nullcontext(existing_connection)
        with manager as connection:
            if existing_connection is None:
                connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT id, effective_label FROM messages WHERE account_id = ? AND message_key = ?",
                (message["account_id"], message["message_key"]),
            ).fetchone()
            message_id = existing["id"] if existing else message["id"]
            previous_folders = []
            if existing:
                previous_folders = [
                    row["path"]
                    for row in connection.execute(
                        """
                        SELECT folders.path FROM message_locations
                        JOIN folders ON folders.id = message_locations.folder_id
                        WHERE message_locations.message_id = ? AND message_locations.present = 1
                          AND folders.role IN ('ham', 'spam', 'monitored')
                          AND message_locations.folder_id != ?
                        """,
                        (message_id, location["folder_id"]),
                    ).fetchall()
                ]
            label = message.get("effective_label")
            if existing and existing["effective_label"] == "spam":
                label = "spam"
            connection.execute(
                """
                INSERT INTO messages(
                    id, account_id, message_key, rfc_message_id, content_sha256,
                    from_header, sender_domain, subject, received_at, raw_storage_path,
                    effective_label, label_source, model_text, preprocessing_version,
                    privacy_counts_json, processed_at, first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id, message_key) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    mailbox_status = 'present',
                    effective_label = CASE WHEN messages.label_source IN ('dashboard', 'automated_move') THEN messages.effective_label ELSE ? END,
                    label_source = CASE WHEN messages.label_source IN ('dashboard', 'automated_move') THEN messages.label_source ELSE COALESCE(excluded.label_source, messages.label_source) END,
                    model_text = excluded.model_text,
                    preprocessing_version = excluded.preprocessing_version,
                    privacy_counts_json = excluded.privacy_counts_json,
                    processed_at = excluded.processed_at
                """,
                (
                    message_id, message["account_id"], message["message_key"], message.get("rfc_message_id"),
                    message["content_sha256"], message.get("from_header", ""), message.get("sender_domain"),
                    message.get("subject", ""), message.get("received_at"), message["raw_storage_path"],
                    label, message.get("label_source"), message.get("model_text"),
                    message.get("preprocessing_version"), json.dumps(message.get("privacy_counts", {})),
                    now if message.get("model_text") else None, now, now, label,
                ),
            )
            connection.execute(
                """
                INSERT INTO message_locations(
                    id, message_id, folder_id, uid_validity, uid, first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(folder_id, uid_validity, uid) DO UPDATE SET
                    present = 1, last_seen_at = excluded.last_seen_at
                """,
                (location["id"], message_id, location["folder_id"], location["uid_validity"], location["uid"], now, now),
            )
            if previous_folders:
                new_folder = connection.execute(
                    "SELECT path FROM folders WHERE id = ?", (location["folder_id"],)
                ).fetchone()
                connection.execute(
                    "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'folder_move', ?, ?, 'imap_reconciliation', ?)",
                    (message_id, json.dumps(previous_folders), new_folder["path"] if new_folder else None, now),
                )
            if existing_connection is None:
                connection.commit()
            return str(message_id)

    def create_prediction(self, values: dict) -> dict:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO predictions(
                    id, message_id, model_group_id, model_version_id, score, threshold,
                    label, action_mode, action_status, source_folder_id,
                    source_uid_validity, source_uid, destination_folder_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["id"], values["message_id"], values["model_group_id"],
                    values["model_version_id"], values["score"], values["threshold"],
                    values["label"], values["action_mode"], values["action_status"],
                    values.get("source_folder_id"), values.get("source_uid_validity"),
                    values.get("source_uid"), values.get("destination_folder_id"), now,
                ),
            )
            connection.execute(
                """INSERT INTO message_events(
                       message_id, event_type, old_value, new_value, source, created_at
                   ) VALUES (?, 'prediction', NULL, ?, 'mail_nuke_model', ?)""",
                (
                    values["message_id"],
                    json.dumps(
                        {
                            "prediction_id": values["id"], "score": values["score"],
                            "threshold": values["threshold"], "label": values["label"],
                            "model_version_id": values["model_version_id"],
                        }
                    ),
                    now,
                ),
            )
            connection.commit()
            row = connection.execute("SELECT * FROM predictions WHERE id = ?", (values["id"],)).fetchone()
            return dict(row)

    def finish_prediction_action(
        self, prediction_id: str, status: str, error: str | None = None
    ) -> None:
        if status not in {"moved", "failed"}:
            raise ValueError("Prediction action status must be moved or failed")
        now = utc_now()
        with self.connect() as connection:
            prediction = connection.execute(
                "SELECT * FROM predictions WHERE id = ?", (prediction_id,)
            ).fetchone()
            if prediction is None:
                raise KeyError(prediction_id)
            connection.execute(
                """UPDATE predictions SET action_status = ?, error_summary = ?, actioned_at = ?
                   WHERE id = ?""",
                (status, error[:500] if error else None, now, prediction_id),
            )
            if status == "moved":
                connection.execute(
                    """UPDATE messages SET label_source = 'automated_move', label_changed_at = ?
                       WHERE id = ? AND label_source IS NULL""",
                    (now, prediction["message_id"]),
                )
            connection.execute(
                """INSERT INTO message_events(
                       message_id, event_type, old_value, new_value, source, created_at
                   ) VALUES (?, 'automated_move', NULL, ?, 'mail_nuke_automation', ?)""",
                (
                    prediction["message_id"],
                    json.dumps({"prediction_id": prediction_id, "status": status, "error": error}),
                    now,
                ),
            )
            connection.commit()

    def latest_prediction(self, message_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM predictions WHERE message_id = ? ORDER BY created_at DESC LIMIT 1",
                (message_id,),
            ).fetchone()
            return dict(row) if row else None

    def deployment_readiness(self) -> dict:
        accounts = []
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT accounts.id, accounts.display_name, accounts.automation_mode,
                    accounts.spam_destination_folder_id,
                    model_groups.active_model_version_id,
                    EXISTS(SELECT 1 FROM folders WHERE account_id = accounts.id
                           AND role IN ('ham', 'monitored')) AS has_source_folder,
                    EXISTS(SELECT 1 FROM folders WHERE account_id = accounts.id
                           AND role = 'spam') AS has_spam_folder,
                    EXISTS(SELECT 1 FROM jobs WHERE account_id = accounts.id
                           AND kind = 'initial_index' AND status IN ('queued', 'running')) AS indexing,
                    (SELECT status FROM jobs WHERE account_id = accounts.id
                     AND kind = 'initial_index' ORDER BY created_at DESC LIMIT 1) AS index_status,
                    (SELECT error_summary FROM jobs WHERE account_id = accounts.id
                     AND status = 'failed' ORDER BY created_at DESC LIMIT 1) AS latest_error
                FROM accounts JOIN model_groups ON model_groups.id = accounts.model_group_id
                WHERE accounts.enabled = 1 ORDER BY accounts.display_name COLLATE NOCASE
                """
            ).fetchall()
        for row in rows:
            checks = {
                "folders": bool(row["has_source_folder"]) and bool(row["has_spam_folder"]),
                "index": row["index_status"] == "completed" and not bool(row["indexing"]),
                "model": bool(row["active_model_version_id"]),
                "automation": row["automation_mode"] in {"observe", "move"},
            }
            blockers = []
            if bool(row["indexing"]) or row["index_status"] != "completed":
                blockers.append("Initial indexing is not complete")
            if not row["active_model_version_id"]:
                blockers.append("No active model")
            if not bool(row["has_source_folder"]):
                blockers.append("No ham or monitored source folder")
            if not bool(row["has_spam_folder"]):
                blockers.append("No Spam folder")
            observe_ready = not blockers
            if row["latest_error"]:
                readiness_status = "error"
            elif bool(row["indexing"]):
                readiness_status = "indexing"
            elif not checks["folders"]:
                readiness_status = "setup_required"
            elif not checks["index"]:
                readiness_status = "ready_to_index"
            elif not checks["model"]:
                readiness_status = "model_required"
            elif row["automation_mode"] == "off":
                readiness_status = "ready_to_enable"
            else:
                readiness_status = "active"
            accounts.append(
                {
                    "id": row["id"], "display_name": row["display_name"],
                    "automation_mode": row["automation_mode"],
                    "ready_to_observe": observe_ready,
                    "ready": observe_ready and checks["automation"],
                    "status": readiness_status,
                    "checks": checks,
                    "blockers": blockers,
                    "latest_error": row["latest_error"],
                }
            )
        return {
            "ready": bool(accounts) and all(account["ready"] for account in accounts),
            "accounts": accounts,
        }

    def account_message_counts(self, account_id: str) -> dict:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                    SUM(CASE WHEN effective_label = 'ham' THEN 1 ELSE 0 END) AS ham,
                    SUM(CASE WHEN effective_label = 'spam' THEN 1 ELSE 0 END) AS spam,
                    SUM(CASE WHEN effective_label IS NULL THEN 1 ELSE 0 END) AS unlabelled
                FROM messages WHERE account_id = ?
                """,
                (account_id,),
            ).fetchone()
            return {key: int(row[key] or 0) for key in ("total", "ham", "spam", "unlabelled")}

    def known_location(self, folder_id: str, uid_validity: int, uid: int) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM message_locations WHERE folder_id = ? AND uid_validity = ? AND uid = ?",
                (folder_id, uid_validity, uid),
            ).fetchone()
            return row is not None

    def create_reconcile_job(self, job_id: str, account_id: str) -> dict:
        if self.get_account(account_id) is None:
            raise KeyError(account_id)
        now = utc_now()
        with self.connect() as connection:
            initialized = connection.execute(
                """SELECT EXISTS(SELECT 1 FROM folders WHERE account_id = ?
                                  AND role IN ('ham', 'spam', 'monitored')) AS has_folders,
                          EXISTS(SELECT 1 FROM jobs WHERE account_id = ?
                                  AND kind = 'initial_index' AND status = 'completed') AS indexed""",
                (account_id, account_id),
            ).fetchone()
            if not bool(initialized["has_folders"]):
                raise RuntimeError("Configure mailbox folder roles before syncing")
            if not bool(initialized["indexed"]):
                raise RuntimeError("Complete the initial mailbox index before syncing")
            existing = connection.execute(
                "SELECT id FROM jobs WHERE account_id = ? AND kind = 'reconcile_account' AND status IN ('queued', 'running')",
                (account_id,),
            ).fetchone()
            if existing:
                return self.get_job(existing["id"])
            connection.execute(
                "INSERT INTO jobs(id, kind, status, account_id, created_at) VALUES (?, 'reconcile_account', 'queued', ?, ?)",
                (job_id, account_id, now),
            )
            connection.commit()
        return self.get_job(job_id)

    def queue_due_reconciliations(self, interval_seconds: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=interval_seconds)).isoformat()
        queued = 0
        with self.connect() as connection:
            accounts = connection.execute(
                """
                SELECT accounts.id, MAX(COALESCE(jobs.finished_at, jobs.created_at)) AS last_run
                FROM accounts LEFT JOIN jobs
                    ON jobs.account_id = accounts.id AND jobs.kind = 'reconcile_account'
                WHERE accounts.enabled = 1
                  AND EXISTS(SELECT 1 FROM folders WHERE account_id = accounts.id
                             AND role IN ('ham', 'spam', 'monitored'))
                  AND EXISTS(SELECT 1 FROM jobs initial_jobs
                             WHERE initial_jobs.account_id = accounts.id
                               AND initial_jobs.kind = 'initial_index'
                               AND initial_jobs.status = 'completed')
                GROUP BY accounts.id
                """
            ).fetchall()
        for account in accounts:
            if account["last_run"] is None or account["last_run"] < cutoff:
                self.create_reconcile_job(f"reconcile-{account['id']}-{int(datetime.now().timestamp())}", account["id"])
                queued += 1
        return queued

    def finalize_reconciliation(
        self, account_id: str, seen_locations: set[tuple[str, int, int]]
    ) -> dict:
        now = utc_now()
        changed = {"moved": 0, "deleted": 0, "relabeled": 0}
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            folders = connection.execute(
                "SELECT id FROM folders WHERE account_id = ? AND role IN ('ham', 'spam', 'monitored')",
                (account_id,),
            ).fetchall()
            folder_ids = {row["id"] for row in folders}
            locations = connection.execute(
                """
                SELECT message_locations.* FROM message_locations
                JOIN messages ON messages.id = message_locations.message_id
                WHERE messages.account_id = ? AND message_locations.folder_id IN (
                    SELECT id FROM folders WHERE account_id = ? AND role IN ('ham', 'spam', 'monitored')
                )
                """,
                (account_id, account_id),
            ).fetchall()
            affected = set()
            for location in locations:
                key = (location["folder_id"], int(location["uid_validity"]), int(location["uid"]))
                present = key in seen_locations
                if present:
                    connection.execute(
                        "UPDATE message_locations SET present = 1, last_seen_at = ? WHERE id = ?",
                        (now, location["id"]),
                    )
                elif bool(location["present"]):
                    connection.execute(
                        "UPDATE message_locations SET present = 0 WHERE id = ?",
                        (location["id"],),
                    )
                    affected.add(location["message_id"])

            message_rows = connection.execute(
                "SELECT * FROM messages WHERE account_id = ?", (account_id,)
            ).fetchall()
            for message in message_rows:
                present_roles = {
                    row["role"]
                    for row in connection.execute(
                        """
                        SELECT folders.role FROM message_locations
                        JOIN folders ON folders.id = message_locations.folder_id
                        WHERE message_locations.message_id = ? AND message_locations.present = 1
                        """,
                        (message["id"],),
                    ).fetchall()
                }
                old_status = message["mailbox_status"]
                new_status = "present" if present_roles else "deleted"
                if old_status != new_status:
                    connection.execute(
                        "UPDATE messages SET mailbox_status = ?, deleted_detected_at = ? WHERE id = ?",
                        (new_status, now if new_status == "deleted" else None, message["id"]),
                    )
                    connection.execute(
                        "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'mailbox_status', ?, ?, 'imap_reconciliation', ?)",
                        (message["id"], old_status, new_status, now),
                    )
                    changed["deleted" if new_status == "deleted" else "moved"] += 1

                if message["label_source"] == "dashboard":
                    continue
                if message["label_source"] == "automated_move" and "ham" not in present_roles:
                    new_label = message["effective_label"]
                else:
                    new_label = "ham" if "ham" in present_roles else ("spam" if "spam" in present_roles else message["effective_label"])
                if new_label != message["effective_label"]:
                    connection.execute(
                        "UPDATE messages SET effective_label = ?, label_source = 'folder_reconciliation', label_changed_at = ? WHERE id = ?",
                        (new_label, now, message["id"]),
                    )
                    connection.execute(
                        "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'effective_label', ?, ?, 'folder_reconciliation', ?)",
                        (message["id"], message["effective_label"], new_label, now),
                    )
                    changed["relabeled"] += 1
            for folder_id in folder_ids:
                connection.execute(
                    "UPDATE folders SET last_reconciled_at = ? WHERE id = ?", (now, folder_id)
                )
            connection.commit()
        return changed

    def list_messages(
        self,
        account_id: str | None = None,
        group_id: str | None = None,
        label: str | None = None,
        mailbox_status: str | None = None,
        training_status: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        clauses = ["1 = 1"]
        params: list[Any] = []
        for column, value in (
            ("messages.account_id", account_id),
            ("accounts.model_group_id", group_id),
            ("messages.effective_label", label),
            ("messages.mailbox_status", mailbox_status),
            ("messages.training_status", training_status),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if search:
            tokens = re.findall(r"\w+", search.casefold(), flags=re.UNICODE)
            if tokens:
                clauses.append(
                    "messages.rowid IN (SELECT rowid FROM messages_search WHERE messages_search MATCH ?)"
                )
                params.append(" AND ".join(f'"{token}"*' for token in tokens))
        where = " AND ".join(clauses)
        with self.connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM messages JOIN accounts ON accounts.id = messages.account_id WHERE {where}",
                params,
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT messages.id, messages.account_id, accounts.display_name AS account_name,
                    accounts.model_group_id, messages.from_header, messages.sender_domain,
                    messages.subject, messages.received_at, messages.mailbox_status,
                    messages.training_status, messages.effective_label, messages.label_source,
                    messages.last_seen_at, messages.deleted_detected_at,
                    (SELECT score FROM predictions WHERE message_id = messages.id
                     ORDER BY created_at DESC LIMIT 1) AS latest_score,
                    (SELECT label FROM predictions WHERE message_id = messages.id
                     ORDER BY created_at DESC LIMIT 1) AS predicted_label,
                    (SELECT action_status FROM predictions WHERE message_id = messages.id
                     ORDER BY created_at DESC LIMIT 1) AS prediction_action_status
                FROM messages JOIN accounts ON accounts.id = messages.account_id
                WHERE {where}
                ORDER BY COALESCE(
                    julianday(messages.received_at),
                    julianday(messages.last_seen_at)
                ) DESC,
                julianday(messages.last_seen_at) DESC,
                messages.id DESC
                LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
            return {"total": int(total), "items": [dict(row) for row in rows]}

    def sender_classification_export(
        self,
        account_id: str | None = None,
        group_id: str | None = None,
        label: str | None = None,
        entity: str = "all",
    ) -> list[dict]:
        if label not in {None, "ham", "spam"}:
            raise ValueError("Label must be ham or spam")
        if entity not in {"all", "domain", "email"}:
            raise ValueError("Entity must be all, domain, or email")
        clauses = ["messages.effective_label IN ('ham', 'spam')", "messages.training_status != 'purged'"]
        params: list[Any] = []
        for column, value in (
            ("messages.account_id", account_id),
            ("accounts.model_group_id", group_id),
            ("messages.effective_label", label),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT messages.account_id, messages.from_header, messages.sender_domain,
                    messages.effective_label, messages.first_seen_at, messages.last_seen_at
                FROM messages JOIN accounts ON accounts.id = messages.account_id
                WHERE {' AND '.join(clauses)}
                """,
                params,
            ).fetchall()

        aggregates: dict[tuple[str, str, str], dict] = {}
        for row in rows:
            email_address = parseaddr(row["from_header"] or "")[1].strip().casefold()
            if "@" not in email_address:
                email_address = ""
            domain = (
                email_address.rsplit("@", 1)[1]
                if email_address
                else str(row["sender_domain"] or "").strip().casefold()
            )
            values = []
            if entity in {"all", "email"} and email_address:
                values.append(("email", email_address))
            if entity in {"all", "domain"} and domain:
                values.append(("domain", domain))
            for entity_type, value in values:
                key = (entity_type, value, row["effective_label"])
                aggregate = aggregates.setdefault(
                    key,
                    {
                        "entity_type": entity_type,
                        "value": value,
                        "label": row["effective_label"],
                        "message_count": 0,
                        "account_ids": set(),
                        "first_seen_at": row["first_seen_at"],
                        "last_seen_at": row["last_seen_at"],
                    },
                )
                aggregate["message_count"] += 1
                aggregate["account_ids"].add(row["account_id"])
                aggregate["first_seen_at"] = min(
                    aggregate["first_seen_at"], row["first_seen_at"]
                )
                aggregate["last_seen_at"] = max(
                    aggregate["last_seen_at"], row["last_seen_at"]
                )

        result = []
        for aggregate in aggregates.values():
            aggregate["account_count"] = len(aggregate.pop("account_ids"))
            result.append(aggregate)
        return sorted(
            result,
            key=lambda item: (
                item["entity_type"], -item["message_count"], item["value"], item["label"]
            ),
        )
    def update_message_review(
        self, message_id: str, label: str | None = None, training_status: str | None = None
    ) -> dict:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
            if row is None:
                raise KeyError(message_id)
            if label is not None and label != row["effective_label"]:
                connection.execute(
                    "UPDATE messages SET effective_label = ?, label_source = 'dashboard', label_changed_at = ? WHERE id = ?",
                    (label, now, message_id),
                )
                connection.execute(
                    "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'effective_label', ?, ?, 'dashboard', ?)",
                    (message_id, row["effective_label"], label, now),
                )
            if training_status is not None and training_status != row["training_status"]:
                connection.execute(
                    "UPDATE messages SET training_status = ?, training_status_changed_at = ? WHERE id = ?",
                    (training_status, now, message_id),
                )
                connection.execute(
                    "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'training_status', ?, ?, 'dashboard', ?)",
                    (message_id, row["training_status"], training_status, now),
                )
            connection.commit()
            result = connection.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
            return dict(result)

    def create_manual_spam_move_job(self, job_id: str, message_id: str) -> dict | None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            message = connection.execute(
                """SELECT messages.*, accounts.spam_destination_folder_id
                   FROM messages JOIN accounts ON accounts.id = messages.account_id
                   WHERE messages.id = ?""",
                (message_id,),
            ).fetchone()
            if message is None:
                raise KeyError(message_id)
            destination = connection.execute(
                """SELECT * FROM folders WHERE id = ? AND account_id = ? AND role = 'spam'""",
                (message["spam_destination_folder_id"], message["account_id"]),
            ).fetchone()
            if destination is None:
                raise RuntimeError(
                    "Choose a Spam destination for this mailbox before marking messages as spam"
                )
            source = connection.execute(
                """SELECT message_locations.*, folders.path, folders.role
                   FROM message_locations JOIN folders ON folders.id = message_locations.folder_id
                   WHERE message_locations.message_id = ? AND message_locations.present = 1
                     AND folders.id != ?
                   ORDER BY CASE folders.role WHEN 'ham' THEN 0 WHEN 'monitored' THEN 1 ELSE 2 END
                   LIMIT 1""",
                (message_id, destination["id"]),
            ).fetchone()
            connection.execute(
                "UPDATE messages SET effective_label = 'spam', label_source = 'dashboard', label_changed_at = ? WHERE id = ?",
                (now, message_id),
            )
            if message["effective_label"] != "spam":
                connection.execute(
                    "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'effective_label', ?, 'spam', 'dashboard', ?)",
                    (message_id, message["effective_label"], now),
                )
            if source is None:
                connection.commit()
                return None
            existing = connection.execute(
                """SELECT id FROM jobs WHERE kind = 'manual_spam_move'
                   AND status IN ('queued', 'running')
                   AND json_extract(context_json, '$.message_id') = ?""",
                (message_id,),
            ).fetchone()
            if existing:
                connection.commit()
                return self.get_job(existing["id"])
            context = {
                "message_id": message_id,
                "source_folder_id": source["folder_id"],
                "source_path": source["path"],
                "source_uid_validity": int(source["uid_validity"]),
                "source_uid": int(source["uid"]),
                "destination_folder_id": destination["id"],
                "destination_path": destination["path"],
            }
            connection.execute(
                """INSERT INTO jobs(id, kind, status, account_id, context_json, created_at)
                   VALUES (?, 'manual_spam_move', 'queued', ?, ?, ?)""",
                (job_id, message["account_id"], json.dumps(context), now),
            )
            connection.commit()
        return self.get_job(job_id)

    def finish_manual_spam_move(self, message_id: str, source_folder_id: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE message_locations SET present = 0
                   WHERE message_id = ? AND folder_id = ?""",
                (message_id, source_folder_id),
            )
            connection.execute(
                """UPDATE messages SET mailbox_status = 'moved', label_source = 'dashboard',
                       label_changed_at = ? WHERE id = ?""",
                (now, message_id),
            )
            connection.execute(
                """INSERT INTO message_events(
                       message_id, event_type, old_value, new_value, source, created_at
                   ) VALUES (?, 'manual_spam_move', NULL, 'moved', 'dashboard', ?)""",
                (message_id, now),
            )
            connection.commit()
    def purge_message(self, message_id: str) -> str:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
            if row is None:
                raise KeyError(message_id)
            raw_path = row["raw_storage_path"]
            connection.execute(
                """
                UPDATE messages SET training_status = 'purged', from_header = '', sender_domain = NULL,
                    subject = '', model_text = NULL, raw_storage_path = '', training_status_changed_at = ?
                WHERE id = ?
                """,
                (now, message_id),
            )
            connection.execute(
                "INSERT INTO message_events(message_id, event_type, old_value, new_value, source, created_at) VALUES (?, 'training_status', ?, 'purged', 'dashboard', ?)",
                (message_id, row["training_status"], now),
            )
            connection.commit()
            return str(raw_path)

    def raw_path_reference_count(self, raw_path: str) -> int:
        if not raw_path:
            return 0
        with self.connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM messages WHERE raw_storage_path = ?", (raw_path,)
                ).fetchone()[0]
            )

    def message_events(self, message_id: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM message_events WHERE message_id = ? ORDER BY created_at DESC, id DESC",
                (message_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def create_training_job(self, job_id: str, group_id: str) -> dict:
        if self.get_model_group(group_id) is None:
            raise KeyError(group_id)
        context = json.dumps({"group_id": group_id})
        with self.connect() as connection:
            existing = connection.execute(
                """SELECT id FROM jobs
                   WHERE kind = 'train_model' AND status IN ('queued', 'running')
                     AND json_extract(context_json, '$.group_id') = ?""",
                (group_id,),
            ).fetchone()
            if existing:
                return self.get_job(existing["id"])
            connection.execute(
                "INSERT INTO jobs(id, kind, status, context_json, created_at) VALUES (?, 'train_model', 'queued', ?, ?)",
                (job_id, context, utc_now()),
            )
            connection.commit()
        return self.get_job(job_id)

    def queue_due_training(self, interval_seconds: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=interval_seconds)).isoformat()
        queued = 0
        with self.connect() as connection:
            groups = connection.execute(
                """
                SELECT model_groups.id,
                    (SELECT MAX(COALESCE(jobs.finished_at, jobs.created_at)) FROM jobs
                     WHERE jobs.kind = 'train_model'
                       AND json_extract(jobs.context_json, '$.group_id') = model_groups.id) AS last_attempt,
                    (SELECT COUNT(*) FROM messages JOIN accounts ON accounts.id = messages.account_id
                     JOIN privacy_profiles ON privacy_profiles.model_group_id = model_groups.id
                     WHERE accounts.model_group_id = model_groups.id
                       AND messages.training_status = 'included'
                       AND messages.effective_label IN ('ham', 'spam')
                       AND messages.model_text IS NOT NULL
                       AND messages.preprocessing_version = privacy_profiles.version) AS sample_count
                FROM model_groups
                """
            ).fetchall()
        for group in groups:
            if int(group["sample_count"] or 0) >= 8 and (
                group["last_attempt"] is None or group["last_attempt"] < cutoff
            ):
                self.create_training_job(
                    f"train-{group['id']}-{int(datetime.now().timestamp())}", group["id"]
                )
                queued += 1
        return queued

    def training_source_messages(self, group_id: str, privacy_version: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT messages.id, messages.content_sha256, messages.model_text,
                    messages.effective_label, messages.label_source, messages.label_changed_at
                FROM messages JOIN accounts ON accounts.id = messages.account_id
                WHERE accounts.model_group_id = ?
                  AND messages.training_status = 'included'
                  AND messages.effective_label IN ('ham', 'spam')
                  AND messages.model_text IS NOT NULL
                  AND messages.preprocessing_version = ?
                ORDER BY messages.id
                """,
                (group_id, privacy_version),
            ).fetchall()
            return [dict(row) for row in rows]

    def create_dataset_generation(
        self, generation_id: str, group_id: str, privacy_version: int,
        samples: list[dict], deduplicated: int, ambiguous: int,
    ) -> dict:
        ham = sum(sample["label"] == "ham" for sample in samples)
        spam = sum(sample["label"] == "spam" for sample in samples)
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO dataset_generations(
                    id, model_group_id, privacy_profile_version, status,
                    total_samples, ham_samples, spam_samples,
                    deduplicated_samples, ambiguous_samples, created_at
                ) VALUES (?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?)
                """,
                (generation_id, group_id, privacy_version, len(samples), ham, spam, deduplicated, ambiguous, now),
            )
            connection.executemany(
                """
                INSERT INTO training_samples(
                    dataset_generation_id, message_id, label, split, content_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (generation_id, sample["message_id"], sample["label"], sample["split"], sample["content_sha256"])
                    for sample in samples
                ],
            )
            connection.commit()
        return self.get_dataset_generation(generation_id)

    def get_dataset_generation(self, generation_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM dataset_generations WHERE id = ?", (generation_id,)
            ).fetchone()
            return dict(row) if row else None

    def dataset_rows(self, generation_id: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT training_samples.*, messages.model_text FROM training_samples
                JOIN messages ON messages.id = training_samples.message_id
                WHERE training_samples.dataset_generation_id = ?
                ORDER BY training_samples.split, training_samples.message_id
                """,
                (generation_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def create_model_version(
        self, version_id: str, group_id: str, generation_id: str,
        artifact_path: str, threshold: float, metrics: dict, status: str,
    ) -> dict:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO model_versions(
                    id, model_group_id, dataset_generation_id, artifact_path,
                    recommended_threshold, metrics_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (version_id, group_id, generation_id, artifact_path, threshold, json.dumps(metrics), status, utc_now()),
            )
            connection.commit()
        return self.get_model_version(version_id)

    def get_model_version(self, version_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM model_versions WHERE id = ?", (version_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["metrics"] = json.loads(result.pop("metrics_json"))
            return result

    def active_model_version(self, group_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT model_versions.* FROM model_groups
                JOIN model_versions ON model_versions.id = model_groups.active_model_version_id
                WHERE model_groups.id = ?
                """,
                (group_id,),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["metrics"] = json.loads(result.pop("metrics_json"))
            return result

    def promote_model_version(self, group_id: str, version_id: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE model_versions SET status = 'superseded' WHERE model_group_id = ? AND status = 'active'",
                (group_id,),
            )
            connection.execute(
                "UPDATE model_versions SET status = 'active', activated_at = ? WHERE id = ? AND model_group_id = ?",
                (now, version_id, group_id),
            )
            connection.execute(
                "UPDATE model_groups SET active_model_version_id = ?, updated_at = ? WHERE id = ?",
                (version_id, now, group_id),
            )
            connection.commit()

    def reject_model_version(self, version_id: str) -> None:
        with self.connect() as connection:
            connection.execute("UPDATE model_versions SET status = 'rejected' WHERE id = ?", (version_id,))
            connection.commit()

    def model_group_status(self, group_id: str) -> dict:
        group = self.get_model_group(group_id)
        if group is None:
            raise KeyError(group_id)
        profile = self.get_privacy_profile(group_id)
        active = self.active_model_version(group_id)
        with self.connect() as connection:
            versions = connection.execute(
                "SELECT id FROM model_versions WHERE model_group_id = ? ORDER BY created_at DESC LIMIT 20",
                (group_id,),
            ).fetchall()
            jobs = connection.execute(
                """SELECT * FROM jobs
                   WHERE kind = 'train_model'
                     AND json_extract(context_json, '$.group_id') = ?
                   ORDER BY created_at DESC LIMIT 10""",
                (group_id,),
            ).fetchall()
        threshold = group["threshold_override"]
        if threshold is None and active:
            threshold = active["recommended_threshold"]
        return {
            "group": dict(group), "privacy_version": profile["version"] if profile else None,
            "active_model": active, "effective_threshold": threshold,
            "versions": [self.get_model_version(row["id"]) for row in versions],
            "jobs": [dict(row) for row in jobs],
        }

    def set_threshold_override(self, group_id: str, threshold: float | None) -> dict:
        if threshold is not None and not 0 <= threshold <= 1:
            raise ValueError("Threshold must be between 0 and 1")
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE model_groups SET threshold_override = ?, updated_at = ? WHERE id = ?",
                (threshold, utc_now(), group_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(group_id)
            connection.commit()
        return self.model_group_status(group_id)

    def get_privacy_profile(self, group_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM privacy_profiles WHERE model_group_id = ?", (group_id,)
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["user_names"] = json.loads(result.pop("user_names_json"))
            result["custom_emails"] = json.loads(result.pop("custom_emails_json"))
            result["normalize_other_emails"] = bool(result["normalize_other_emails"])
            return result

    def group_email_addresses(self, group_id: str) -> list[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT email_address FROM accounts WHERE model_group_id = ? ORDER BY email_address",
                (group_id,),
            ).fetchall()
            return [str(row["email_address"]).strip().casefold() for row in rows]

    def update_privacy_profile(
        self,
        group_id: str,
        user_names: list[str],
        custom_emails: list[str],
        normalize_other_emails: bool,
        known_secrets_ciphertext: str | None,
        replace_secrets: bool,
    ) -> dict:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM privacy_profiles WHERE model_group_id = ?", (group_id,)
            ).fetchone()
            if row is None:
                raise KeyError(group_id)
            secret_value = known_secrets_ciphertext if replace_secrets else row["known_secrets_ciphertext"]
            connection.execute(
                """
                UPDATE privacy_profiles SET
                    version = version + 1,
                    user_names_json = ?, custom_emails_json = ?,
                    known_secrets_ciphertext = ?, normalize_other_emails = ?, updated_at = ?
                WHERE model_group_id = ?
                """,
                (
                    json.dumps(user_names), json.dumps(custom_emails), secret_value,
                    int(normalize_other_emails), now, group_id,
                ),
            )
            connection.commit()
        return self.get_privacy_profile(group_id)

    def create_reprocess_job(self, job_id: str, group_id: str) -> dict:
        now = utc_now()
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT id FROM jobs WHERE kind = 'reprocess_privacy' AND status IN ('queued', 'running') AND context_json = ?",
                (json.dumps({"group_id": group_id}),),
            ).fetchone()
            if existing:
                return self.get_job(existing["id"])
            connection.execute(
                """
                INSERT INTO jobs(id, kind, status, created_at, context_json)
                VALUES (?, 'reprocess_privacy', 'queued', ?, ?)
                """,
                (job_id, now, json.dumps({"group_id": group_id})),
            )
            connection.commit()
        return self.get_job(job_id)

    def claim_next_job(self) -> dict | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            connection.execute(
                "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?",
                (utc_now(), row["id"]),
            )
            connection.commit()
            return self.get_job(row["id"])

    def group_messages_for_reprocessing(self, group_id: str, version: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT messages.* FROM messages
                JOIN accounts ON accounts.id = messages.account_id
                WHERE accounts.model_group_id = ?
                  AND messages.training_status != 'purged'
                  AND COALESCE(messages.preprocessing_version, 0) != ?
                ORDER BY messages.id
                """,
                (group_id, version),
            ).fetchall()
            return [dict(row) for row in rows]

    def update_message_preprocessing(
        self, message_id: str, model_text: str, version: int, counts: dict
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE messages SET model_text = ?, preprocessing_version = ?,
                    privacy_counts_json = ?, processed_at = ? WHERE id = ?
                """,
                (model_text, version, json.dumps(counts), utc_now(), message_id),
            )
            connection.commit()
