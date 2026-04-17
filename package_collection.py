from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_PART_SIZE = 1900 * 1024 * 1024


def md5_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(data: dict) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_tar_mode(path: Path) -> str:
    if path.suffixes[-2:] == [".tar", ".gz"]:
        return "w:gz"
    if path.suffixes[-2:] == [".tar", ".bz2"]:
        return "w:bz2"
    if path.suffixes[-2:] == [".tar", ".xz"]:
        return "w:xz"
    return "w"


@dataclass
class PackageEntry:
    source: Path
    relpath: str
    size: int


def chunk_entries(entries: list[PackageEntry], part_size: int) -> list[list[PackageEntry]]:
    parts: list[list[PackageEntry]] = []
    current: list[PackageEntry] = []
    current_size = 0

    for entry in entries:
        if current and current_size + entry.size > part_size:
            parts.append(current)
            current = []
            current_size = 0

        current.append(entry)
        current_size += entry.size

    if current:
        parts.append(current)

    return parts


def write_archive(entries: list[PackageEntry], archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, get_tar_mode(archive_path)) as tar:
        for entry in entries:
            tar.add(entry.source, arcname=entry.relpath, recursive=False)


def compress_with_zstd(input_path: Path, output_path: Path) -> None:
    zstd = shutil.which("zstd")
    if not zstd:
        raise RuntimeError("zstd not found in PATH")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [zstd, "-q", "-19", "--force", str(input_path), "-o", str(output_path)],
        check=True,
    )


def build_part_archives(
    entries: list[PackageEntry],
    prefix: str,
    out_dir: Path,
    part_size: int,
) -> list[dict]:
    parts_meta: list[dict] = []
    part_groups = chunk_entries(entries, part_size)

    for idx, part_entries in enumerate(part_groups, start=1):
        tar_name = f"{prefix}.part{idx:02d}.tar"
        tar_path = out_dir / tar_name
        zst_path = out_dir / f"{tar_name}.zst"
        write_archive(part_entries, tar_path)
        compress_with_zstd(tar_path, zst_path)
        tar_path.unlink()
        parts_meta.append(
            {
                "archive": zst_path.name,
                "entries": len(part_entries),
                "bytes": zst_path.stat().st_size,
                "members": [entry.relpath for entry in part_entries],
            }
        )

    return parts_meta


def iter_bsim_exports(bsim_dir: Path) -> Iterable[Path]:
    for path in sorted(bsim_dir.glob("sigs_*")):
        if path.is_file():
            yield path


def build_binary_rows(
    collection_id: str,
    binaries_dir: Path,
    bsim_dir: Path,
) -> tuple[list[dict], list[PackageEntry], list[PackageEntry]]:
    binary_entries: list[PackageEntry] = []
    bsim_entries: list[PackageEntry] = []
    rows: list[dict] = []

    bsim_by_md5: dict[str, Path] = {}
    for export_path in iter_bsim_exports(bsim_dir):
        parts = export_path.name.split("_", 2)
        if len(parts) < 3:
            continue
        bsim_by_md5[parts[1].lower()] = export_path

    for binary_path in sorted(p for p in binaries_dir.iterdir() if p.is_file()):
        sha256 = sha256_file(binary_path)
        md5 = md5_file(binary_path)
        binary_relpath = f"cas/{sha256[:2]}/{sha256}.bin"
        binary_entries.append(
            PackageEntry(binary_path, binary_relpath, binary_path.stat().st_size)
        )

        row = {
            "collection_id": collection_id,
            "sha256": sha256,
            "md5": md5,
            "filename": binary_path.name,
            "original_path": None,
            "os": None,
            "arch": None,
            "version": None,
            "file_build": None,
            "source_url": None,
            "binary_relpath": binary_relpath,
            "binary_archive": None,
            "binary_archive_member": binary_relpath,
            "bsim_relpath": None,
            "bsim_archive": None,
            "bsim_archive_member": None,
            "pdb_status": None,
            "pdb_guid": None,
            "pdb_age": None,
        }

        export_path = bsim_by_md5.get(md5)
        if export_path:
            bsim_relpath = f"cas/{sha256[:2]}/{sha256}.sigs.xml"
            bsim_entries.append(
                PackageEntry(export_path, bsim_relpath, export_path.stat().st_size)
            )
            row["bsim_relpath"] = bsim_relpath
            row["bsim_archive_member"] = bsim_relpath

        rows.append(row)

    return rows, binary_entries, bsim_entries

def patch_row_archive_locations(
    rows: list[dict],
    binary_parts: list[dict],
    bsim_parts: list[dict],
) -> None:
    binary_members = {
        member: part["archive"] for part in binary_parts for member in part["members"]
    }
    bsim_members = {
        member: part["archive"] for part in bsim_parts for member in part["members"]
    }
    for row in rows:
        row["binary_archive"] = binary_members.get(row["binary_archive_member"])
        if row["bsim_archive_member"]:
            row["bsim_archive"] = bsim_members.get(row["bsim_archive_member"])


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--collection-name", required=True)
    parser.add_argument("--mode", choices=["baseline-image", "manifest-driven"], required=True)
    parser.add_argument("--binaries-dir", default="bins/downloaded")
    parser.add_argument("--bsim-dir", default="ghidrecomps/bsim-xmls")
    parser.add_argument("--out-dir", default="collections_build")
    parser.add_argument("--runner-label")
    parser.add_argument("--runner-image-version")
    parser.add_argument("--ghidra-version", required=True)
    parser.add_argument("--ghidra-bsim-compat-version", required=True)
    parser.add_argument("--bsim-template", required=True)
    parser.add_argument("--collected-at", required=True)
    parser.add_argument("--notes", default="")
    parser.add_argument("--analysis-options-json")
    parser.add_argument("--scope", nargs="*")
    parser.add_argument("--selection-reason", default="")
    parser.add_argument("--part-size-bytes", type=int, default=DEFAULT_PART_SIZE)
    args = parser.parse_args()

    binaries_dir = Path(args.binaries_dir)
    bsim_dir = Path(args.bsim_dir)
    out_dir = Path(args.out_dir) / args.collection_id
    out_dir.mkdir(parents=True, exist_ok=True)

    analysis_options = {}
    if args.analysis_options_json:
        analysis_options = json.loads(Path(args.analysis_options_json).read_text())

    rows, binary_entries, bsim_entries = build_binary_rows(
        args.collection_id, binaries_dir, bsim_dir
    )

    binary_parts = build_part_archives(binary_entries, "binaries", out_dir, args.part_size_bytes)
    bsim_parts = build_part_archives(bsim_entries, "bsim", out_dir, args.part_size_bytes)
    patch_row_archive_locations(rows, binary_parts, bsim_parts)

    manifest_path = out_dir / "manifest.jsonl"
    write_jsonl(manifest_path, rows)
    compress_with_zstd(manifest_path, out_dir / "manifest.jsonl.zst")
    manifest_path.unlink()

    toolchain_lock = {
        "collection_id": args.collection_id,
        "ghidra_version": args.ghidra_version,
        "ghidra_bsim_compat_version": args.ghidra_bsim_compat_version,
        "bsim_template": args.bsim_template,
        "analysis_options_hash": sha256_json(analysis_options),
        "analysis_options": analysis_options,
        "runner_label": args.runner_label,
        "runner_image_version": args.runner_image_version,
    }
    toolchain_lock_path = out_dir / "toolchain.lock.json"
    toolchain_lock_path.write_text(json.dumps(toolchain_lock, indent=2, sort_keys=True))

    collection_meta = {
        "collection_id": args.collection_id,
        "mode": args.mode,
        "name": args.collection_name,
        "selection_reason": args.selection_reason,
        "runner_label": args.runner_label,
        "runner_image_version": args.runner_image_version,
        "ghidra_version": args.ghidra_version,
        "ghidra_bsim_compat_version": args.ghidra_bsim_compat_version,
        "bsim_template": args.bsim_template,
        "collected_at": args.collected_at,
        "scope": args.scope or [],
        "notes": args.notes,
        "toolchain_lock": toolchain_lock_path.name,
        "binary_parts": binary_parts,
        "bsim_parts": bsim_parts,
        "binary_count": len(rows),
        "bsim_count": sum(1 for row in rows if row["bsim_relpath"]),
    }
    collection_meta_path = out_dir / "collection.json"
    collection_meta_path.write_text(json.dumps(collection_meta, indent=2, sort_keys=True))

    print(json.dumps(collection_meta, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
