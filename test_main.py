import tempfile
import unittest
from pathlib import Path

import main


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_trailing_slash(self):
        self.assertEqual(main.validate_target("http://127.0.0.1:8000"), "http://127.0.0.1:8000/")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            main.validate_target("file:///etc/passwd")

    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            main.validate_target("http://user:pass@example.com")

    def test_rejects_query(self):
        with self.assertRaises(ValueError):
            main.validate_target("http://example.com/?x=1")


class WordlistTests(unittest.TestCase):
    def test_deduplicates_and_skips_invalid_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "words.txt"
            file_path.write_text("admin\n/admin\n../secret\nhttps://evil.test\n# comment\napi\n", encoding="utf-8")
            self.assertEqual(main.load_wordlist(str(file_path)), ["admin", "api"])

    def test_build_url_encodes_percent_and_keeps_target_origin(self):
        url = main.build_url("http://127.0.0.1:8000/", "folder/a%2Fb")
        self.assertEqual(url, "http://127.0.0.1:8000/folder/a%252Fb")

    def test_build_url_rejects_traversal(self):
        with self.assertRaises(ValueError):
            main.build_url("http://127.0.0.1:8000/", "../secret")


class ScanResultTests(unittest.TestCase):
    def test_status_filter(self):
        result = main.ScanResult("http://localhost/", 200, 12, 1.2)
        self.assertTrue(main.is_interesting(result, {200, 403}))
        self.assertFalse(main.is_interesting(result, {403}))

    def test_error_result_is_not_interesting(self):
        result = main.ScanResult("http://localhost/", 0, -1, 1.2, "ConnectionError")
        self.assertFalse(main.is_interesting(result, {200, 403}))


if __name__ == "__main__":
    unittest.main()
