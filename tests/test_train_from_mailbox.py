from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trainer.train_from_mailbox import folder_names, replace_managed_export


class TrainFromMailboxTests(unittest.TestCase):
    def test_folder_names_supports_multiple_mailboxes(self):
        self.assertEqual(folder_names("INBOX, Archive/Receipts, "), ["INBOX", "Archive/Receipts"])

    def test_managed_export_replacement_preserves_sibling_manual_exports(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / "staged"
            destination = root / "exports" / "ham" / "mailbox"
            manual = root / "exports" / "ham" / "manual.eml"
            staged.mkdir()
            destination.mkdir(parents=True)
            manual.write_bytes(b"manual")
            (destination / "old.eml").write_bytes(b"old")
            (staged / "new.eml").write_bytes(b"new")
            replace_managed_export(staged, destination)
            self.assertTrue(manual.exists())
            self.assertFalse((destination / "old.eml").exists())
            self.assertEqual((destination / "new.eml").read_bytes(), b"new")


if __name__ == "__main__":
    unittest.main()
