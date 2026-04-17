from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class PackageCollectionTest(unittest.TestCase):
    def test_smoke_package_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "out"
            cmd = [
                "python3",
                str(ROOT / "package_collection.py"),
                "--collection-id",
                "windows-2022-test",
                "--collection-name",
                "windows-2022 test",
                "--mode",
                "baseline-image",
                "--binaries-dir",
                str(FIXTURES / "binaries"),
                "--bsim-dir",
                str(FIXTURES / "bsim"),
                "--meta-dir",
                str(FIXTURES / "meta"),
                "--out-dir",
                str(out_dir),
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
                "2026-04-17T13:15:00Z",
                "--analysis-options-json",
                str(FIXTURES / "analysis.json"),
                "--scope",
                r"C:\Windows\System32",
                r"C:\Windows\SysWOW64",
                "--selection-reason",
                "fixture test",
                "--part-size-bytes",
                "50",
            ]
            subprocess.run(cmd, check=True, cwd=ROOT)

            collection_dir = out_dir / "windows-2022-test"
            manifest = subprocess.check_output(
                ["zstd", "-d", "-q", "-c", str(collection_dir / "manifest.jsonl.zst")],
                text=True,
            )
            rows = [json.loads(line) for line in manifest.splitlines() if line.strip()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["os"], "windows")
            self.assertEqual(rows[0]["arch"], "x64")
            self.assertEqual(rows[0]["file_build"], "20348")
            self.assertEqual(rows[0]["binary_archive"], "binaries.part01.tar.zst")
            self.assertEqual(rows[0]["bsim_archive"], "bsim.part01.tar.zst")
            self.assertEqual(rows[1]["arch"], "x86")
            self.assertEqual(rows[1]["source_dataset"], "windows-2022-test")

            toolchain_lock = json.loads((collection_dir / "toolchain.lock.json").read_text())
            self.assertEqual(toolchain_lock["ghidra_version"], "11.2.1")
            self.assertIn("analysis_options_hash", toolchain_lock)

            collection_meta = json.loads((collection_dir / "collection.json").read_text())
            self.assertEqual(collection_meta["binary_count"], 2)
            self.assertEqual(collection_meta["bsim_count"], 2)


if __name__ == "__main__":
    unittest.main()
