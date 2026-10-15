"""Pruebas del instalador de iconos (sin red: usa un ZIP de prueba)."""
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import icons  # noqa: E402
from catalog import COMPONENTS  # noqa: E402

SVG = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64"/></svg>'


class IconsTest(unittest.TestCase):
    def test_every_component_has_icon_except_note(self):
        ids = {c["id"] for c in COMPONENTS} - {"note", "subnet"}
        self.assertEqual(sorted(ids - set(icons.ICON_MAP)), [])

    def test_setup_from_zip(self):
        with tempfile.TemporaryDirectory() as base:
            zpath = os.path.join(base, "pkg.zip")
            with zipfile.ZipFile(zpath, "w") as z:
                z.writestr("Architecture-Service-Icons/Arch_Storage/64/Arch_Amazon-Simple-Storage-Service_64.svg", SVG)
                z.writestr("__MACOSX/Architecture-Service-Icons/._Arch_AWS-Lambda_64.svg", b"junk")
                z.writestr("Architecture-Service-Icons/Arch_Compute/64/Arch_AWS-Lambda_64.svg",
                           b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
                z.writestr("../../evil/Arch_Amazon-EC2_64.svg", SVG)
            res = icons.setup_icons(base, zip_path=zpath, log=lambda *_: None)
            out = icons.icons_dir(base)
            self.assertTrue(os.path.exists(os.path.join(out, "s3.svg")))
            self.assertFalse(os.path.exists(os.path.join(out, "lambda.svg")))  # SVG con script rechazado
            self.assertIn("lambda", res["missing"])
            # La ruta del ZIP nunca se usa: el archivo queda con nombre fijo dentro de la carpeta de iconos
            self.assertTrue(os.path.exists(os.path.join(out, "ec2.svg")))
            self.assertFalse(os.path.exists(os.path.join(base, "..", "evil")))
            self.assertIn("s3", icons.available(base)["available"])

    def test_invalid_zip(self):
        with tempfile.TemporaryDirectory() as base:
            bad = os.path.join(base, "x.zip")
            with open(bad, "wb") as fh:
                fh.write(b"not a zip")
            with self.assertRaises(ValueError):
                icons.setup_icons(base, zip_path=bad, log=lambda *_: None)


if __name__ == "__main__":
    unittest.main()
