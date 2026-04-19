# learn-workflow

Collection harness for building Windows binary corpora, packaging BSim exports, and preparing data for hosted BSim databases.

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Design Notes](docs/DESIGN.md)
- [Operations](docs/OPERATIONS.md)

## Current v1 shape

- `gen_files.py`: builds manifest-driven worklists from `cvedata`
- `get_files.py`: downloads binaries and records metadata in `bins/meta`
- `run_decomp.py`: runs `ghidrecomp` with `--bsim --gzf`
- `package_collection.py`: packages binaries and BSim XML into multipart release assets with a manifest and `toolchain.lock`
- `build_bsim_db.sh`: imports packaged BSim XML into a PostgreSQL-backed BSim database
- `bsim_db_tool.py`: local wrapper for creating/importing/querying BSim databases via Ghidra's `support/bsim`

The current v1 target is:

- Windows only
- pinned base images like `windows-2022` and `windows-2025`
- `System32` and `SysWOW64` first
- binaries + BSim XML + manifest + `toolchain.lock`
- per-image database dumps later, not for every narrow run

## Current Proven Path

This repo has now proven the following path:

1. collect a bounded Windows baseline subset from a GitHub-hosted runner
2. install pinned Ghidra on that runner
3. install latest `ghidrecomp` from PyPI
4. generate real BSim XML from a runner-collected system DLL
5. package binaries + BSim XML + manifest + toolchain lock
6. import the resulting XML into a local BSim database
7. query executables and functions from that database

The next supported path is a bounded baseline run driven by a committed allowlist:

```bash
python3 collect_baseline.py \
  --root /path/to/System32 \
  --root /path/to/SysWOW64 \
  --allowlist allowlists/windows-2022-seed.txt \
  --out-dir collections_build/baseline_collect \
  --limit 6 \
  --runner-label windows-2022 \
  --source-dataset windows-2022-baseline-allowlist

Use `allowlists/windows-2022-core.txt` with sharding for slower, broader baseline corpus runs.

For baseline runs, raw `ghidrecomp` output is now optional and disabled by default. Keep it off unless you need debugging detail beyond the packaged BSim XML and manifests.

The workflow now passes the selected `bsim_template` through to `ghidrecomp` so the generated XML matches the value recorded in `toolchain.lock.json`.
```

## Local packaging smoke test

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Local packaging command

```bash
python3 package_collection.py \
  --collection-id windows-2022-smoke \
  --collection-name "windows-2022 smoke" \
  --mode baseline-image \
  --binaries-dir bins/downloaded \
  --bsim-dir ghidrecomps/bsim-xmls \
  --meta-dir bins/meta \
  --out-dir collections_build/out \
  --runner-label windows-2022 \
  --runner-image-version 20260414.1.0 \
  --ghidra-version 11.2.1 \
  --ghidra-bsim-compat-version 6.0 \
  --bsim-template medium_64 \
  --collected-at 2026-04-17T13:15:00Z
```

This writes:

- `manifest.jsonl.zst`
- `toolchain.lock.json`
- `collection.json`
- `binaries.partNN.tar.zst`
- `bsim.partNN.tar.zst`

## BSim import

```bash
./build_bsim_db.sh /path/to/ghidra \
  postgresql://user:pass@host:5432/windows_2022 \
  /path/to/bsim-xmls \
  ghidra://corpus/windows-2022
```

## Local BSim DB query

Create a local file-backed BSim DB from exported XML:

```bash
python3 bsim_db_tool.py \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  build \
  --db-url file:/tmp/testcorpus \
  --xml-dir /path/to/bsim-xmls \
  --config-template medium_64
```

List executables in the DB:

```bash
python3 bsim_db_tool.py \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  listexes \
  --db-url file:/tmp/testcorpus
```

List functions for one executable:

```bash
python3 bsim_db_tool.py \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  listfuncs \
  --db-url file:/tmp/testcorpus \
  --name dnsapi.dll.x64.10.0.20348.3692 \
  --maxfunc 10
```

This wrapper currently covers DB lifecycle and metadata queries. Similarity searching is not exposed by the `support/bsim` CLI directly, so your future MCP server will likely need either:

- a Ghidra-side API integration for similarity queries, or
- a separate service layer that wraps Ghidra/BSim internals beyond the CLI.

## Import packaged BSim

Extract BSim XML from a packaged collection:

```bash
python3 import_packaged_bsim.py extract \
  --collection-dir collections_build/out/windows-2022-smoke \
  --out-dir /tmp/windows-2022-smoke-bsim
```

Build or append a DB directly from a packaged collection:

```bash
python3 import_packaged_bsim.py build \
  --collection-dir collections_build/out/windows-2022-smoke \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  --db-url postgresql://user:pass@host:5432/windows_2022 \
  --config-template medium_64 \
  --override ghidra://corpus/windows-2022/smoke
```
