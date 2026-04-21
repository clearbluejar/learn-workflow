from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from curation_harness import bsim_db_tool


def extract_zstd_tar(archive_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    zstd = shutil.which("zstd")
    if zstd:
        proc = subprocess.Popen(
            [zstd, "-d", "-q", "-c", str(archive_path)],
            stdout=subprocess.PIPE,
        )
        assert proc.stdout is not None
        try:
            with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
                tar.extractall(out_dir, filter="data")
        finally:
            rc = proc.wait()
            if rc != 0:
                raise subprocess.CalledProcessError(rc, [zstd, "-d", "-q", "-c", str(archive_path)])
        return

    try:
        import zstandard
    except ImportError as exc:
        raise RuntimeError("zstd not found in PATH and zstandard is not installed") from exc

    dctx = zstandard.ZstdDecompressor()
    with archive_path.open("rb") as src:
        with dctx.stream_reader(src) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                tar.extractall(out_dir, filter="data")


def collection_id_from_dir(collection_dir: Path) -> str:
    meta_path = collection_dir / "collection.json"
    if meta_path.exists():
        payload = json.loads(meta_path.read_text())
        collection_id = payload.get("collection_id")
        if collection_id:
            return collection_id
    return collection_dir.name


def extract_bsim_archives(collection_dir: Path, out_dir: Path) -> list[Path]:
    archives = sorted(collection_dir.glob("bsim.part*.tar.zst"))
    if not archives:
        raise FileNotFoundError(f"no bsim part archives found in {collection_dir}")

    extracted_paths: list[Path] = []
    for archive in archives:
        extract_zstd_tar(archive, out_dir)
        extracted_paths.append(archive)
    return extracted_paths


def run_bsim_tool(
    ghidra_install_dir: Path,
    command: str,
    db_url: str,
    xml_dir: Path,
    config_template: str | None = None,
    override: str | None = None,
    allow_existing: bool = False,
) -> int:
    argv = [
        "--ghidra-install-dir",
        str(ghidra_install_dir),
        command,
        "--db-url",
        db_url,
        "--xml-dir",
        str(xml_dir),
    ]
    if config_template:
        argv.extend(["--config-template", config_template])
    if override:
        argv.extend(["--override", override])
    if allow_existing:
        argv.append("--allow-existing")

    parser = bsim_db_tool.build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def cmd_extract(args: argparse.Namespace) -> int:
    extract_bsim_archives(args.collection_dir, args.out_dir)
    print(
        json.dumps(
            {
                "collection_id": collection_id_from_dir(args.collection_dir),
                "out_dir": str(args.out_dir),
                "xml_count": len(list(args.out_dir.rglob("*.xml"))),
            },
            indent=2,
        )
    )
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="import-packaged-bsim-") as temp_dir:
        xml_dir = Path(temp_dir) / "bsim-xmls"
        extract_bsim_archives(args.collection_dir, xml_dir)
        return run_bsim_tool(
            args.ghidra_install_dir,
            "import",
            args.db_url,
            xml_dir,
            override=args.override,
        )


def cmd_build(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="import-packaged-bsim-") as temp_dir:
        xml_dir = Path(temp_dir) / "bsim-xmls"
        extract_bsim_archives(args.collection_dir, xml_dir)
        return run_bsim_tool(
            args.ghidra_install_dir,
            "build",
            args.db_url,
            xml_dir,
            config_template=args.config_template,
            override=args.override,
            allow_existing=args.allow_existing,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Extract BSim XML from packaged collection artifacts and import/build a BSim database.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract = subparsers.add_parser("extract")
    extract.add_argument("--collection-dir", required=True, type=Path)
    extract.add_argument("--out-dir", required=True, type=Path)
    extract.set_defaults(func=cmd_extract)

    import_cmd = subparsers.add_parser("import")
    import_cmd.add_argument("--collection-dir", required=True, type=Path)
    import_cmd.add_argument("--ghidra-install-dir", required=True, type=Path)
    import_cmd.add_argument("--db-url", required=True)
    import_cmd.add_argument("--override")
    import_cmd.set_defaults(func=cmd_import)

    build = subparsers.add_parser("build")
    build.add_argument("--collection-dir", required=True, type=Path)
    build.add_argument("--ghidra-install-dir", required=True, type=Path)
    build.add_argument("--db-url", required=True)
    build.add_argument("--config-template", default="medium_64")
    build.add_argument("--override")
    build.add_argument("--allow-existing", action="store_true")
    build.set_defaults(func=cmd_build)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)
