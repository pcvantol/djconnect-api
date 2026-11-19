"""Verify the exact allowed hosted-runner mirror transformation."""
import unittest
from unittest.mock import patch

from scripts.prepare_browser_apt_mirrors import ORIGINAL, preferred_mirrors, main


class BrowserMirrors(unittest.TestCase):
    def test_existing_archives_preferred_and_idempotent(self):
        original = "".join(f"{uri}\t{priority}\n" for uri, priority in ORIGINAL.items())
        result = preferred_mirrors(original)
        self.assertEqual(result.splitlines(), [
            "https://archive.ubuntu.com/ubuntu/\tpriority:1",
            "https://security.ubuntu.com/ubuntu/\tpriority:2",
            "http://azure.archive.ubuntu.com/ubuntu/\tpriority:3",
        ])
        self.assertEqual(preferred_mirrors(result), result)

    def test_unknown_duplicate_missing_or_changed_rows_fail_before_any_write(self):
        original = "".join(f"{uri}\t{priority}\n" for uri, priority in ORIGINAL.items())
        for bad in [
            "", original + "\n", original.replace("https://archive.ubuntu.com", "https://other.invalid"),
            original.replace("priority:2", "priority:1"),
            "\n".join(original.splitlines()[:2]) + "\n",
            original + original.splitlines()[0] + "\n",
            original.replace("https://security.ubuntu.com/ubuntu/", "https://archive.ubuntu.com/ubuntu/"),
        ]:
            with self.subTest(bad=bad), patch("scripts.prepare_browser_apt_mirrors.Path.read_text", return_value=bad), patch("scripts.prepare_browser_apt_mirrors.Path.write_text") as write:
                with self.assertRaises(ValueError):
                    main()
                write.assert_not_called()

    def test_only_runner_mirrors_and_acquire_bounds_are_written(self):
        original = "".join(f"{uri}\t{priority}\n" for uri, priority in ORIGINAL.items())
        writes = []
        with patch("scripts.prepare_browser_apt_mirrors.Path.read_text", return_value=original), patch("scripts.prepare_browser_apt_mirrors.Path.write_text", autospec=True, side_effect=lambda path, text: writes.append((str(path), text))):
            main()
        self.assertEqual([path for path, _ in writes], ["/etc/apt/apt-mirrors.txt", "/etc/apt/apt.conf.d/zz-djc-browser-acquire"])
        self.assertEqual(writes[1][1], 'Acquire::Retries "1";\nAcquire::http::Timeout "15";\nAcquire::https::Timeout "15";\n')


if __name__ == "__main__":
    unittest.main()
