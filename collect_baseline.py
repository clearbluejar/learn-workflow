from __future__ import annotations

import argparse
import json
import math
import re
import shutil
from pathlib import Path
from typing import Any

import pefile


ARCH_BY_MACHINE = {
    332: "x86",
    34404: "x64",
    43620: "arm64",
}


def clean_filename(filename: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "-", filename)


def get_pe(path: Path) -> pefile.PE:
    return pefile.PE(str(path), fast_load=True)


def get_pe_arch(path: Path) -> str | None:
    try:
        pe = get_pe(path)
        return ARCH_BY_MACHINE.get(pe.FILE_HEADER.Machine)
    except Exception:
        return None


def get_pe_version(path: Path) -> str | None:
    try:
        pe = get_pe(path)
        pe.parse_data_directories([2])
        for fileinfo in pe.FileInfo[0]:
            if fileinfo.Key.decode() != "StringFileInfo":
                continue
            for st in fileinfo.StringTable:
                for key, value in st.entries.items():
                    if key.decode() == "FileVersion":
                        return value.decode().split(" ")[0]
    except Exception:
        return None
    return None


def normalize_value(value: Any) -> Any:
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, dict):
        return {k: normalize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize_value(v) for v in value]
    return value


def iter_candidates(roots: list[Path], recurse: bool) -> list[Path]:
    candidates: list[Path] = []
    for root in roots:
        if recurse:
            candidates.extend(path for path in root.rglob("*") if path.is_file())
        else:
            candidates.extend(path for path in root.iterdir() if path.is_file())
    return sorted(candidates)


def is_pe_candidate(path: Path) -> bool:
    return path.suffix.lower() in {".dll", ".exe", ".sys", ".cpl", ".ocx"}


def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--root", action="append", required=True, help="Root directory to collect from")
    parser.add_argument("--out-dir", default="collections_build/baseline_collect")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--recurse", action="store_true")
    parser.add_argument("--runner-label", required=True)
    parser.add_argument("--source-dataset", required=True)
    args = parser.parse_args()

    roots = [Path(root) for root in args.root]
    out_dir = Path(args.out_dir)
    binaries_dir = out_dir / "binaries"
    meta_dir = out_dir / "meta"
    binaries_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    records = []
    count = 0
    for candidate in iter_candidates(roots, args.recurse):
        if count >= args.limit:
            break
        if not is_pe_candidate(candidate):
            continue

        arch = get_pe_arch(candidate)
        version = get_pe_version(candidate)
        if not arch or not version:
            continue

        copied_name = clean_filename(f"{candidate.name.lower()}.{arch}.{version}")
        copied_path = binaries_dir / copied_name
        shutil.copy2(candidate, copied_path)

        file_meta = {
            "Name": candidate.name,
            "Path": str(candidate),
            "VersionInfo.FileVersion": version,
            "source": args.source_dataset,
            "runner_label": args.runner_label,
        }
        records.append([200, normalize_value(file_meta), version, str(copied_path)])
        count += 1

    (meta_dir / "dl_files0.json").write_text(json.dumps(records, indent=2))
    print(json.dumps({"collected": count, "out_dir": str(out_dir)}, indent=2))


if __name__ == "__main__":
    main()
