from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from unittest.mock import patch

from trainer.weekly_retrain import Metrics, marked_signatures, relabel_restored, should_promote


class WeeklyRetrainTests(unittest.TestCase):
    def test_marked_signatures_joins_dashboard_key_to_action_log(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "actions.jsonl"
            marks = root / "marks.json"
            log.write_text(json.dumps({"ts": "2026-07-01T00:00:00Z", "uid": 42, "from": "A@B.test", "subject": "Miss"}) + "\n")
            marks.write_text(json.dumps({"2026-07-01T00:00:00Z__42": {"mark": "false_negative"}}))
            self.assertEqual(marked_signatures(log, marks), {("a@b.test", "miss")})

    def test_promotion_requires_non_regressing_recall(self):
        current = Metrics(0.8, 0.01)
        self.assertTrue(should_promote(current, Metrics(0.85, 0.014), 0.005))
        self.assertFalse(should_promote(current, Metrics(0.79, 0.0), 0.005))
        self.assertFalse(should_promote(current, Metrics(0.9, 0.016), 0.005))

    def test_restored_message_moves_feedback_from_spam_to_ham(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            observed_dir = root / "observed"
            spam_dir = root / "exports" / "spam" / "feedback"
            observed_dir.mkdir()
            spam_dir.mkdir(parents=True)
            (observed_dir / "abc.eml").write_bytes(b"message")
            (spam_dir / "abc.eml").write_bytes(b"message")
            record = {"digest": "abc", "label": "spam"}
            with patch("trainer.weekly_retrain.ROOT", root), patch("trainer.weekly_retrain.OBSERVED_DIR", observed_dir), patch("trainer.weekly_retrain.FEEDBACK_DIR", spam_dir):
                self.assertTrue(relabel_restored("<id@test>", record))
            self.assertFalse((spam_dir / "abc.eml").exists())
            self.assertEqual((root / "exports" / "ham" / "feedback" / "abc.eml").read_bytes(), b"message")
            self.assertEqual(record["label"], "ham")


if __name__ == "__main__":
    unittest.main()
