"""Check bounded mirror selection without accessing the network or host APT."""
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from scripts.prepare_browser_apt_mirrors import ARCHIVE, AZURE, SECURITY, ORIGINAL, preferred_mirrors, responsive_mirrors, main


class BrowserMirrors(unittest.TestCase):
    def setUp(self):
        self.original = "".join(f"{uri}\t{priority}\n" for uri, priority in ORIGINAL.items())

    def test_reachable_azure_is_prioritized(self):
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch("scripts.prepare_browser_apt_mirrors.urlopen", side_effect=[response, URLError('timeout'), URLError('timeout')]) as probe:
            order = responsive_mirrors('resolute')
        self.assertEqual(order, (AZURE, ARCHIVE, SECURITY))
        self.assertEqual(probe.call_count, 3)
        self.assertTrue(all(call.kwargs['timeout'] == 3 for call in probe.call_args_list))
        self.assertEqual(preferred_mirrors(self.original, order).splitlines()[0], AZURE + '\tpriority:1')

    def test_no_reachable_mirror_fails(self):
        with patch("scripts.prepare_browser_apt_mirrors.urlopen", side_effect=URLError('unavailable')):
            with self.assertRaises(ValueError):
                responsive_mirrors('resolute')

    def test_unknown_duplicate_missing_or_changed_rows_fail_before_any_write(self):
        for bad in ['', self.original + '\n', self.original.replace(ARCHIVE, 'https://other.invalid/'),
                    self.original.replace('priority:2', 'priority:1'), '\n'.join(self.original.splitlines()[:2]) + '\n']:
            with self.subTest(bad=bad), patch('scripts.prepare_browser_apt_mirrors.Path.read_text', return_value=bad), patch('scripts.prepare_browser_apt_mirrors.Path.write_text') as write:
                with self.assertRaises(ValueError):
                    main()
                write.assert_not_called()

    def test_main_writes_only_approved_configuration(self):
        writes = []
        with patch('scripts.prepare_browser_apt_mirrors.Path.read_text', return_value=self.original), \
             patch('scripts.prepare_browser_apt_mirrors.subprocess.check_output', return_value='resolute\n'), \
             patch('scripts.prepare_browser_apt_mirrors.responsive_mirrors', return_value=(AZURE, ARCHIVE, SECURITY)), \
             patch('scripts.prepare_browser_apt_mirrors.Path.write_text', autospec=True, side_effect=lambda path, text: writes.append((str(path), text))):
            main()
        self.assertEqual([path for path, _ in writes], ['/etc/apt/apt-mirrors.txt', '/etc/apt/apt.conf.d/zz-djc-browser-acquire'])
        self.assertEqual(writes[1][1], 'Acquire::Retries "1";\nAcquire::http::Timeout "5";\nAcquire::https::Timeout "5";\n')


if __name__ == '__main__':
    unittest.main()
