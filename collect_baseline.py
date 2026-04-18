from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import sys
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

PREFERRED_NAMES = [
    "dnsapi.dll",
    "comdlg32.dll",
    "searchindexer.exe",
    "dbgeng.dll",
    "imagehlp.dll",
    "mstask.dll",
    "taskhostw.exe",
    "eventvwr.exe",
    "apphelp.dll",
    "url.dll",
]


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


def load_allowlist(allowlist_path: Path) -> list[str]:
    lines = []
    for raw_line in allowlist_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def resolve_allowlist_paths(entries: list[str], roots: list[Path]) -> list[Path]:
    resolved: list[Path] = []
    lower_roots = [(str(root).lower(), root) for root in roots]

    for entry in entries:
        normalized = entry.replace("/", "\\")
        entry_path = Path(normalized)
        if entry_path.exists():
            resolved.append(entry_path)
            continue

        matched = False
        entry_lower = normalized.lower()
        for root_lower, root in lower_roots:
            if entry_lower.startswith(root_lower):
                suffix = normalized[len(str(root)) :].lstrip("\\/")
                candidate = root / Path(suffix)
                if candidate.exists():
                    resolved.append(candidate)
                    matched = True
                    break
        if matched:
            continue

        for _, root in lower_roots:
            candidate = root / Path(normalized)
            if candidate.exists():
                resolved.append(candidate)
                matched = True
                break
        if matched:
            continue

        basename = Path(normalized).name
        for _, root in lower_roots:
            candidate = root / basename
            if candidate.exists():
                resolved.append(candidate)
                matched = True
                break
        if not matched:
            print(json.dumps({"warn_missing_allowlist_entry": entry}), file=sys.stderr)

    deduped = []
    seen = set()
    for path in resolved:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def is_pe_candidate(path: Path) -> bool:
    return path.suffix.lower() in {".dll", ".exe", ".sys", ".cpl", ".ocx"}


def candidate_priority(path: Path) -> tuple[int, int, int, str]:
    name = path.name.lower()
    preferred_rank = next(
        (idx for idx, preferred in enumerate(PREFERRED_NAMES) if name == preferred),
        len(PREFERRED_NAMES),
    )
    suffix = path.suffix.lower()
    suffix_rank = {
        ".exe": 0,
        ".dll": 1,
        ".cpl": 2,
        ".ocx": 3,
        ".sys": 4,
    }.get(suffix, 9)
    size = path.stat().st_size
    return (preferred_rank, suffix_rank, -size, name)


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
    parser.add_argument(
        "--allowlist",
        type=Path,
        help="Optional path to a newline-delimited allowlist of preferred binaries",
    )
    parser.add_argument(
        "--min-size-bytes",
        type=int,
        default=65536,
        help="Skip tiny binaries that are less likely to produce useful BSim output",
    )
    args = parser.parse_args()

    roots = [Path(root) for root in args.root]
    out_dir = Path(args.out_dir)
    binaries_dir = out_dir / "binaries"
    meta_dir = out_dir / "meta"
    binaries_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    if args.allowlist:
        allowlist_entries = load_allowlist(args.allowlist)
        candidate_pool = resolve_allowlist_paths(allowlist_entries, roots)
    else:
        candidate_pool = iter_candidates(roots, args.recurse)

    eligible: list[Path] = []
    for candidate in candidate_pool:
        if not candidate.exists() or not candidate.is_file():
            continue
        if not is_pe_candidate(candidate):
            continue
        if candidate.stat().st_size < args.min_size_bytes:
            continue
        eligible.append(candidate)

    records = []
    count = 0
    for candidate in sorted(eligible, key=candidate_priority):
        if count >= args.limit:
            break
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
    print(
        json.dumps(
            {
                "collected": count,
                "eligible_candidates": len(eligible),
                "out_dir": str(out_dir),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
