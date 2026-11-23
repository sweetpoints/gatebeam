from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from product_version import read_version


class ProductVersionTests(unittest.TestCase):
    def test_strict_semver_declaration(self):
        accepted = (
            b'0.1.0\n', b'1.2.3', b'1.2.3-rc.10\n',
            b'1.2.3-0.0x+001.build-4\n', b'1.2.3+-\n',
        )
        rejected = (
            b'', b'1.2', b'v1.2.3', b'01.2.3', b'1.02.3', b'1.2.03',
            b'1.2.3-01', b'1.2.3-rc.01', b'1.2.3-', b'1.2.3+',
            b'1.2.3+build..id', b'1.2.3\n\n', b' 1.2.3', b'1.2.3 ',
            b'1.2.3\n2.0.0\n', '1.2.3-é'.encode(),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'VERSION'
            with self.assertRaises(FileNotFoundError):
                read_version(path)
            for value in accepted:
                with self.subTest(value=value):
                    path.write_bytes(value)
                    self.assertEqual(read_version(path), value.removesuffix(b'\n').decode())
            for value in rejected:
                with self.subTest(value=value):
                    path.write_bytes(value)
                    with self.assertRaises(ValueError):
                        read_version(path)
