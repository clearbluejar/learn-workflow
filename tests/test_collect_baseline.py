from __future__ import annotations

import json
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CollectBaselineTest(unittest.TestCase):
    @unittest.skipIf(
        importlib.util.find_spec("pefile") is None,
        "pefile is required to exercise collect_baseline.py",
    )
    def test_allowlist_resolver_prefers_matching_pe_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "System32"
            root.mkdir(parents=True)
            (root / "dnsapi.dll").write_bytes(b"MZ" + b"\x00" * 70000)
            (root / "notes.txt").write_text("not a pe")

            allowlist = Path(temp_dir) / "allowlist.txt"
            allowlist.write_text(
                "\n".join(
                    [
                        "# comment",
                        "dnsapi.dll",
                        "missing.dll",
                    ]
                )
            )

            cmd = [
                "python3",
                str(ROOT / "collect_baseline.py"),
                "--root",
                str(root),
                "--out-dir",
                str(Path(temp_dir) / "out"),
                "--limit",
                "5",
                "--runner-label",
                "windows-2022",
                "--source-dataset",
                "fixture-baseline",
                "--allowlist",
                str(allowlist),
                "--min-size-bytes",
                "1",
            ]
            result = subprocess.run(
                cmd,
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["eligible_candidates"], 1)
            self.assertEqual(payload["collected"], 0)
            self.assertIn("warn_missing_allowlist_entry", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
