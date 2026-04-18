# Operations

## Local Validation

### Packaging tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

### Package a local collection

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
  --ghidra-version 12.0.4 \
  --ghidra-bsim-compat-version 6.0 \
  --bsim-template medium_64 \
  --collected-at 2026-04-18T00:00:00Z
```

## Local BSim DB Build

### Build from XML

```bash
python3 bsim_db_tool.py \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  build \
  --db-url file:/tmp/testcorpus \
  --xml-dir /path/to/bsim-xmls \
  --config-template medium_64
```

### Query executables

```bash
python3 bsim_db_tool.py \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  listexes \
  --db-url file:/tmp/testcorpus
```

### Query functions

```bash
python3 bsim_db_tool.py \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  listfuncs \
  --db-url file:/tmp/testcorpus \
  --name dnsapi.dll.x64.10.0.20348.3692 \
  --maxfunc 10
```

## GitHub Actions

### Packaging smoke

- workflow: `package-smoke.yml`
- purpose: validate the packaging contract with fixtures

### Windows dry run

- workflow: `windows-baseline-dry-run.yml`
- purpose: collect a tiny subset from `windows-2022` and package it without BSim generation

### Windows BSim smoke

- workflow: `windows-baseline-bsim-smoke.yml`
- purpose: collect a tiny Windows subset, install Ghidra, run `ghidrecomp --bsim`, and package the results

### Windows allowlist baseline

- workflow: `windows-baseline-allowlist.yml`
- purpose: collect a bounded baseline corpus from a committed allowlist, optionally shard it, run `ghidrecomp --bsim`, and package the results
- default input: `allowlists/windows-2022-seed.txt`
- broader input: `allowlists/windows-2022-core.txt` with `shard_count > 1`
- raw `ghidrecomp` upload: optional, intended for debugging rather than routine baseline collection

## Observed CI Results

### Dry run

The dry-run workflow succeeded on `windows-2022` and produced:

- one multipart binary archive
- manifest
- toolchain lock
- collection metadata

### BSim smoke

The BSim smoke workflow succeeded on `windows-2022` and proved:

- pinned Ghidra install
- latest `ghidrecomp` install from PyPI
- BSim XML generation for a real runner-collected system DLL
- packaging of that XML into the v1 corpus format

One successful richer target was:

- `dnsapi.dll.x64.10.0.20348.3692`

with:

- `2598` functions decompiled
- `2821` BSim signatures generated

## Current Constraints

### H2/file-backed BSim DBs

These are useful for local testing but can produce:

- `Database already in use by another process`

when queried concurrently.

Use PostgreSQL-backed BSim for anything shared or long-lived.

### Similarity query gap

The `support/bsim` CLI covers:

- DB creation
- import
- executable listing
- function listing

It does not provide the full future MCP query surface by itself. Similarity querying will need additional integration work.

## Next Operational Steps

1. Run the committed allowlist baseline on `windows-2022`, preferably sharded.
2. Add a parallel or chunked baseline workflow for larger image coverage.
3. Build a PostgreSQL-backed corpus from produced XML.
4. Add a thin resolver layer around:
   - collection manifest
   - executable listing
   - function listing
5. Define the MCP-facing query contract.
