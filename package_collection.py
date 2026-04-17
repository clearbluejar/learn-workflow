from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


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


def normalize_json_value(value: Any) -> Any:
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, dict):
        return {key: normalize_json_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [normalize_json_value(item) for item in value]
    return value


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


@dataclass
class BinaryMetadata:
    source_url: str | None = None
    original_path: str | None = None
    os: str | None = None
    arch: str | None = None
    version: str | None = None
    file_build: str | None = None
    pdb_status: str | None = None
    pdb_guid: str | None = None
    pdb_age: int | None = None
    source_dataset: str | None = None


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
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if zstd:
        subprocess.run(
            [zstd, "-q", "-19", "--force", str(input_path), "-o", str(output_path)],
            check=True,
        )
        return

    try:
        import zstandard
    except ImportError as exc:
        raise RuntimeError("zstd not found in PATH and zstandard is not installed") from exc

    compressor = zstandard.ZstdCompressor(level=19)
    with input_path.open("rb") as src, output_path.open("wb") as dst:
        compressor.copy_stream(src, dst)


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


def parse_binary_name(binary_path: Path) -> tuple[str | None, str | None]:
    parts = binary_path.name.split(".")
    if len(parts) < 4:
        return None, None
    for idx, part in enumerate(parts):
        if part in {"x86", "x64", "arm64"}:
            version = ".".join(parts[idx + 1 :]) or None
            return part, version
    return None, None


def get_file_build(version: str | None) -> str | None:
    if not version:
        return None
    parts = version.split(".")
    if len(parts) < 3:
        return None
    return parts[2]


def load_metadata_index(meta_dir: Path | None) -> dict[str, BinaryMetadata]:
    if not meta_dir or not meta_dir.exists():
        return {}

    metadata_by_filename: dict[str, BinaryMetadata] = {}
    for dl_meta_path in sorted(meta_dir.glob("dl_files*.json")):
        records = json.loads(dl_meta_path.read_text())
        for record in records:
            if len(record) != 4:
                continue
            _status, source_meta, resolved_version, downloaded_path = record
            source_meta = normalize_json_value(source_meta)
            downloaded_path = Path(downloaded_path)
            parsed_arch, parsed_version = parse_binary_name(downloaded_path)

            pdb_path = source_meta.get("pdb_path")
            metadata_by_filename[downloaded_path.name] = BinaryMetadata(
                source_url=source_meta.get("url"),
                original_path=source_meta.get("Path"),
                os="windows" if source_meta.get("Path") else None,
                arch=parsed_arch,
                version=resolved_version or parsed_version or source_meta.get("VersionInfo.FileVersion"),
                file_build=get_file_build(resolved_version or parsed_version),
                pdb_status="present" if pdb_path else None,
                pdb_guid=source_meta.get("pdb_guid"),
                pdb_age=source_meta.get("pdb_age"),
                source_dataset=source_meta.get("source"),
            )

    return metadata_by_filename


def build_binary_rows(
    collection_id: str,
    binaries_dir: Path,
    bsim_dir: Path,
    metadata_index: dict[str, BinaryMetadata],
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

        metadata = metadata_index.get(binary_path.name, BinaryMetadata())
        parsed_arch, parsed_version = parse_binary_name(binary_path)
        version = metadata.version or parsed_version

        row = {
            "collection_id": collection_id,
            "sha256": sha256,
            "md5": md5,
            "filename": binary_path.name,
            "original_path": metadata.original_path,
            "os": metadata.os,
            "arch": metadata.arch or parsed_arch,
            "version": version,
            "file_build": metadata.file_build or get_file_build(version),
            "source_url": metadata.source_url,
            "source_dataset": metadata.source_dataset,
            "binary_relpath": binary_relpath,
            "binary_archive": None,
            "binary_archive_member": binary_relpath,
            "bsim_relpath": None,
            "bsim_archive": None,
            "bsim_archive_member": None,
            "pdb_status": metadata.pdb_status,
            "pdb_guid": metadata.pdb_guid,
            "pdb_age": metadata.pdb_age,
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
    parser.add_argument("--meta-dir", default="bins/meta")
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
    meta_dir = Path(args.meta_dir) if args.meta_dir else None
    out_dir = Path(args.out_dir) / args.collection_id
    out_dir.mkdir(parents=True, exist_ok=True)

    analysis_options = {}
    if args.analysis_options_json:
        analysis_options = json.loads(Path(args.analysis_options_json).read_text())

    metadata_index = load_metadata_index(meta_dir)
    rows, binary_entries, bsim_entries = build_binary_rows(
        args.collection_id, binaries_dir, bsim_dir, metadata_index
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
        "meta_dir": str(meta_dir) if meta_dir else None,
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
