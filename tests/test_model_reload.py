from pathlib import Path
from unittest.mock import patch
import unittest

from trainer import model_utils


class ModelReloadTests(unittest.TestCase):
    def tearDown(self):
        model_utils._PIPELINE = None
        model_utils._THRESHOLD = None
        model_utils._CLASSES = None
        model_utils._MODEL_MTIME_NS = None

    def test_reloads_only_when_model_file_changes(self):
        first = {"pipeline": "one", "threshold": 0.9, "classes": ["ham", "spam"]}
        second = {"pipeline": "two", "threshold": 0.8, "classes": ["ham", "spam"]}
        with patch.object(Path, "stat") as stat, patch("trainer.model_utils.joblib.load", side_effect=[first, second]) as load:
            stat.return_value.st_mtime_ns = 1
            model_utils.load_model()
            model_utils.load_model()
            stat.return_value.st_mtime_ns = 2
            model_utils.load_model()
        self.assertEqual(load.call_count, 2)
        self.assertEqual(model_utils._PIPELINE, "two")


if __name__ == "__main__":
    unittest.main()
