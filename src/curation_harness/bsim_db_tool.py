from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def run_bsim(ghidra_install_dir: Path, args: list[str]) -> int:
    bsim_bin = ghidra_install_dir / "support" / "bsim"
    if not bsim_bin.exists():
        raise FileNotFoundError(f"Missing bsim utility: {bsim_bin}")

    result = subprocess.run([str(bsim_bin), *args], check=False)
    return result.returncode


def cmd_create(args: argparse.Namespace) -> int:
    bsim_args = ["createdatabase", args.db_url, args.config_template]
    if args.name:
        bsim_args.extend(["--name", args.name])
    if args.owner:
        bsim_args.extend(["--owner", args.owner])
    if args.description:
        bsim_args.extend(["--description", args.description])
    if args.nocallgraph:
        bsim_args.append("--nocallgraph")
    return run_bsim(args.ghidra_install_dir, bsim_args)


def cmd_import(args: argparse.Namespace) -> int:
    bsim_args = ["commitsigs", args.db_url, str(args.xml_dir)]
    if args.md5:
        bsim_args.extend(["--md5", args.md5])
    if args.override:
        bsim_args.extend(["--override", args.override])
    return run_bsim(args.ghidra_install_dir, bsim_args)


def cmd_build(args: argparse.Namespace) -> int:
    create_rc = cmd_create(args)
    if create_rc != 0 and not args.allow_existing:
        return create_rc
    return cmd_import(args)


def cmd_listexes(args: argparse.Namespace) -> int:
    bsim_args = ["listexes", args.db_url]
    if args.md5:
        bsim_args.extend(["--md5", args.md5])
    if args.name:
        bsim_args.extend(["--name", args.name])
    if args.arch:
        bsim_args.extend(["--arch", args.arch])
    if args.compiler:
        bsim_args.extend(["--compiler", args.compiler])
    if args.limit is not None:
        bsim_args.extend(["--limit", str(args.limit)])
    if args.sortcol:
        bsim_args.extend(["--sortcol", args.sortcol])
    if args.includelibs:
        bsim_args.append("--includelibs")
    return run_bsim(args.ghidra_install_dir, bsim_args)


def cmd_listfuncs(args: argparse.Namespace) -> int:
    bsim_args = ["listfuncs", args.db_url]
    if args.md5:
        bsim_args.extend(["--md5", args.md5])
    if args.name:
        bsim_args.extend(["--name", args.name])
    if args.arch:
        bsim_args.extend(["--arch", args.arch])
    if args.compiler:
        bsim_args.extend(["--compiler", args.compiler])
    if args.maxfunc is not None:
        bsim_args.extend(["--maxfunc", str(args.maxfunc)])
    if args.printselfsig:
        bsim_args.append("--printselfsig")
    if args.callgraph:
        bsim_args.append("--callgraph")
    if args.printjustexe:
        bsim_args.append("--printjustexe")
    return run_bsim(args.ghidra_install_dir, bsim_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Thin wrapper around Ghidra's support/bsim utility.",
    )
    parser.add_argument(
        "--ghidra-install-dir",
        required=True,
        type=Path,
        help="Path to the extracted Ghidra installation directory",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--db-url", required=True)
    create.add_argument("--config-template", default="medium_64")
    create.add_argument("--name")
    create.add_argument("--owner")
    create.add_argument("--description")
    create.add_argument("--nocallgraph", action="store_true")
    create.set_defaults(func=cmd_create)

    build = subparsers.add_parser("build")
    build.add_argument("--db-url", required=True)
    build.add_argument("--xml-dir", required=True, type=Path)
    build.add_argument("--config-template", default="medium_64")
    build.add_argument("--name")
    build.add_argument("--owner")
    build.add_argument("--description")
    build.add_argument("--nocallgraph", action="store_true")
    build.add_argument("--override")
    build.add_argument("--md5")
    build.add_argument(
        "--allow-existing",
        action="store_true",
        help="Continue to import signatures even if create returns a non-zero status",
    )
    build.set_defaults(func=cmd_build)

    import_cmd = subparsers.add_parser("import")
    import_cmd.add_argument("--db-url", required=True)
    import_cmd.add_argument("--xml-dir", required=True, type=Path)
    import_cmd.add_argument("--override")
    import_cmd.add_argument("--md5")
    import_cmd.set_defaults(func=cmd_import)

    listexes = subparsers.add_parser("listexes")
    listexes.add_argument("--db-url", required=True)
    listexes.add_argument("--md5")
    listexes.add_argument("--name")
    listexes.add_argument("--arch")
    listexes.add_argument("--compiler")
    listexes.add_argument("--limit", type=int)
    listexes.add_argument("--sortcol", choices=["md5", "name"])
    listexes.add_argument("--includelibs", action="store_true")
    listexes.set_defaults(func=cmd_listexes)

    listfuncs = subparsers.add_parser("listfuncs")
    listfuncs.add_argument("--db-url", required=True)
    listfuncs.add_argument("--md5")
    listfuncs.add_argument("--name")
    listfuncs.add_argument("--arch")
    listfuncs.add_argument("--compiler")
    listfuncs.add_argument("--maxfunc", type=int)
    listfuncs.add_argument("--printselfsig", action="store_true")
    listfuncs.add_argument("--callgraph", action="store_true")
    listfuncs.add_argument("--printjustexe", action="store_true")
    listfuncs.set_defaults(func=cmd_listfuncs)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)
