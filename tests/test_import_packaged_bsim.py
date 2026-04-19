from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class ImportPackagedBsimTest(unittest.TestCase):
    def test_extract_packaged_bsim_parts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            collection_root = temp / "out"
            package_cmd = [
                "python3",
                str(ROOT / "package_collection.py"),
                "--collection-id",
                "windows-2022-import-test",
                "--collection-name",
                "windows-2022 import test",
                "--mode",
                "baseline-image",
                "--binaries-dir",
                str(FIXTURES / "binaries"),
                "--bsim-dir",
                str(FIXTURES / "bsim"),
                "--meta-dir",
                str(FIXTURES / "meta"),
                "--out-dir",
                str(collection_root),
                "--runner-label",
                "windows-2022",
                "--runner-image-version",
                "test-image",
                "--ghidra-version",
                "11.2.1",
                "--ghidra-bsim-compat-version",
                "6.0",
                "--bsim-template",
                "medium_64",
                "--collected-at",
                "2026-04-18T00:00:00Z",
                "--part-size-bytes",
                "50",
            ]
            subprocess.run(package_cmd, check=True, cwd=ROOT)

            extract_dir = temp / "extracted"
            extract_cmd = [
                "python3",
                str(ROOT / "import_packaged_bsim.py"),
                "extract",
                "--collection-dir",
                str(collection_root / "windows-2022-import-test"),
                "--out-dir",
                str(extract_dir),
            ]
            output = subprocess.check_output(extract_cmd, cwd=ROOT, text=True)
            payload = json.loads(output)

            self.assertEqual(payload["collection_id"], "windows-2022-import-test")
            self.assertEqual(payload["xml_count"], 2)
            self.assertTrue((extract_dir / "cas").exists())


if __name__ == "__main__":
    unittest.main()
