# Design Notes

## Core Decisions

### 1. Binaries are the primary durable artifact

Original binaries are stored first because they are:

- smaller than GZFs
- sufficient to regenerate later products
- the cleanest content-addressed object for a corpus

BSim XML is kept alongside them because it is directly ingestible into BSim databases.

### 2. GZFs are deferred

GZFs are useful, but expensive.

The design treats them as a later cache layer rather than a v1 storage requirement. The retrieval path is based on:

- binary identity
- manifest metadata
- later optional GZF regeneration or selective GZF retention

### 3. Manifest is authoritative

The BSim database is a search index, not the source of truth.

The manifest answers:

- what was collected
- from where
- under which toolchain
- where the binary lives inside multipart archives
- where the BSim XML lives inside multipart archives

### 4. Toolchain lock is mandatory

BSim signatures are only meaningful when tied to a specific toolchain context.

At minimum the lock records:

- Ghidra version
- BSim compatibility version
- BSim template
- analysis options hash
- runner label
- runner image version

This prevents silent drift across runs and gives the later backend a stable ingestion contract.

### 5. Baseline-image and manifest-driven are the only two collection modes

This is deliberate.

`baseline-image` captures a reproducible corpus from a known OS image.

`manifest-driven` handles targeted corpora without baking any specific selection semantics into the harness itself.

Anything more would add complexity without increasing leverage in v1.

## Object Identity

Per binary:

- `sha256` is the primary archive identity
- `md5` is retained because BSim surfaces it in lookups

This split is intentional.

`sha256` is the right long-term storage key. `md5` is an adapter key for current BSim interfaces.

## Archive Layout

The packaging scripts use logical CAS-like paths inside multipart archives:

- `cas/<sha256[:2]>/<sha256>.bin`
- `cas/<sha256[:2]>/<sha256>.sigs.xml`

That preserves stable logical identity while still packaging output into release-friendly multipart tarballs.

The manifest stores both:

- logical relative path
- physical archive member and archive filename

This keeps repackaging possible later without changing object identity.

## Baseline Selection Strategy

The baseline collector does not try to fully rank the world.

It uses a cheap priority model:

- known richer binary names first
- then by file type preference
- then by size
- tiny binaries skipped by default

This is a practical compromise:

- fast enough for runner use
- good enough to pick meaningful smoke-test targets

For larger baseline runs, selection can later be replaced with a committed allowlist or a manifest generated offline.

The first committed baseline input now lives under `allowlists/`, starting with `allowlists/windows-2022-core.txt`. These files are intentionally neutral harness inputs rather than embedding research-specific logic in workflow definitions.

## Database Strategy

### Local validation

Local H2/file-backed databases are useful for:

- smoke tests
- query-path validation
- CLI integration checks

They are not the intended shared backend.

### Shared backend

The intended backend is PostgreSQL-backed BSim.

Reasons:

- concurrency
- fewer file-lock issues
- better fit for a service or MCP layer
- suitable as a long-lived query backend

Per-image milestone DB dumps are compatible with this design, but they should be treated as distributable snapshots, not the only operational model.

## Service Boundary

The future MCP server should not own artifact truth.

It should sit on top of:

- packaged corpus artifacts
- manifest metadata
- a BSim backend

A clean contract for the future service is:

- `ingest_collection`
- `list_executables`
- `list_functions`
- `resolve_md5`
- later: `find_similar`

Today the repo supports everything except true similarity query wrapping.

## What Is Proven

The following are already proven:

- bounded Windows baseline collection from GitHub-hosted runners
- packaging into v1 artifact format
- Ghidra install on a Windows runner
- `ghidrecomp --bsim` execution on runner-collected binaries
- local import of real emitted BSim XML into a BSim DB
- executable and function enumeration from the DB

The next design step is not architectural. It is scale and operational refinement.
