# Operations

## Local Validation

### Install the harness package

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

The repo-root scripts still work, but the package entry points are the cleaner long-term interface.

### Bootstrap manifest-driven env

```bash
./bootstrap_manifest_env.sh
```

This creates `.venv-gen`, installs `gen_files.py` dependencies, and downloads the current published `cvedata` data bundle into the venv.

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

Equivalent package command:

```bash
curation-package \
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

### Build from packaged collection

```bash
python3 import_packaged_bsim.py build \
  --collection-dir collections_build/out/windows-2022-smoke \
  --ghidra-install-dir /path/to/ghidra_12.0.4_PUBLIC \
  --db-url postgresql://user:pass@host:5432/windows_2022 \
  --config-template medium_64 \
  --override ghidra://corpus/windows-2022/smoke
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

### Artifact check

- workflow: `artifact-check.yml`
- purpose: validate the packaging contract with fixtures

### Image curation

- workflow: `image-curation.yml`
- purpose: collect a bounded baseline corpus from a committed allowlist, optionally shard it, run `ghidrecomp --bsim`, and package the results
- runtime interface: installs the local package and calls `curation-collect` and `curation-package`
- default input: `allowlists/windows-2022-seed.txt`
- broader input: `allowlists/windows-2022-core.txt` with `shard_count > 1`
- raw `ghidrecomp` upload: optional, intended for debugging rather than routine baseline collection
- `bsim_template` is passed through to `ghidrecomp` and should match the value recorded in collection metadata

### Index refresh

- workflow: `index-refresh.yml`
- purpose: download one packaged artifact from a prior run and import its BSim XML into a PostgreSQL-backed BSim database
- runtime interface: installs the local package and calls `curation-import-bsim`
- required secret: `BSIM_DB_URL`
- optional secret: `BSIM_NAMESPACE_PREFIX`

### Archive sync

- workflow: `archive-sync.yml`
- purpose: download one packaged artifact from a prior run and publish its files as release assets into a private collections repo
- required secrets:
  - `COLLECTIONS_REPO`
  - `COLLECTIONS_PAT`
- inputs:
  - `source_run_id`
  - `artifact_name`
  - `release_tag`
  - optional `release_title`
  - optional `clobber`

This keeps the public repo limited to orchestration while durable corpus storage happens in the private release store.

## Observed CI Results

The current validation path has proven:

- pinned Ghidra install on `windows-2022`
- latest `ghidrecomp` install from PyPI
- BSim XML generation for real runner-collected system DLLs
- packaging of binaries + BSim XML into the v1 corpus format

## Manifest-driven Example

The manifest-driven selector has also been exercised locally with a fresh `cvedata` query. Example:

```bash
cd /tmp
/Users/yoda/Documents/repos/learn-workflow/.venv-gen/bin/python \
  /Users/yoda/Documents/repos/learn-workflow/gen_files.py \
  --include source=windows-2022-10.0.20348.3091 \
  --count 2 \
  --limit-list 4
```

Observed result:

- query matched `44424` rows in the dataset
- output was sharded into `/tmp/gen_files/files0.json` and `/tmp/gen_files/files1.json`
- metadata was written under `/tmp/gen_files/meta/`

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
3. Build a PostgreSQL-backed corpus from produced XML or packaged artifacts.
4. Add a thin resolver layer around:
   - collection manifest
   - executable listing
   - function listing
5. Define the MCP-facing query contract.
