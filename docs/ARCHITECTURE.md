# Architecture

## Purpose

This repo is an orchestration harness for collecting operating system binaries, generating BSim exports with Ghidra, packaging those artifacts, and preparing them for later ingestion into queryable BSim databases.

The current v1 scope is Windows-first:

- pinned GitHub Actions runner images
- `C:\Windows\System32`
- `C:\Windows\SysWOW64`
- original binaries as the primary durable artifact
- BSim XML as the search-index source artifact
- packaged collections that can be stored in a separate private corpus repo

## Repository Split

The intended system has two repositories.

Public repo:

- orchestration code
- collection harnesses
- packaging scripts
- test fixtures
- GitHub Actions workflows
- no committed vulnerability-hunting query logic

Private `collections` repo:

- packaged binaries
- packaged BSim XML
- collection manifests
- toolchain locks
- later: milestone PostgreSQL dumps for baseline image corpora

The public repo produces artifacts. The private repo stores durable corpora. Nothing in the design depends on the public repo retaining large datasets.

## High-Level Flow

There are two collection modes.

### `baseline-image`

Used for bounded collection directly from a runner image.

1. Select binaries from one or more roots on the host OS image.
2. Copy binaries into a normalized staging directory.
3. Emit minimal `bins/meta`-style metadata.
4. Run `ghidrecomp --bsim` on the staged binaries.
5. Package binaries, BSim XML, and metadata into multipart archives.

### `manifest-driven`

Used when a target list is produced elsewhere.

1. Build file lists from `cvedata` or another neutral manifest source.
2. Download binaries and preserve metadata in `bins/meta`.
3. Run `ghidrecomp --bsim`.
4. Package outputs the same way as `baseline-image`.

In practice this path depends on an isolated Python environment plus a published `cvedata` data bundle, because the code package and the data release may not always land at the same version at the same time.

## Data Plane

The data model deliberately separates:

- search index material: BSim XML and later BSim DB rows
- durable corpus material: original binaries
- retrieval metadata: manifest + toolchain lock

### Primary artifact

The original binary is the primary durable artifact.

Reasons:

- smaller than GZF
- can be reprocessed later
- supports regeneration of GZF and BSim with a pinned toolchain

### Secondary artifact

BSim XML is kept because it is the direct import source for the BSim database and is substantially cheaper to store than full GZFs.

### Deferred artifact

GZFs are intentionally deferred in v1. They are a cache, not the source of truth.

## Packaging Model

Each packaged collection currently emits:

- `manifest.jsonl.zst`
- `toolchain.lock.json`
- `collection.json`
- `binaries.partNN.tar.zst`
- `bsim.partNN.tar.zst`

The logical identifier is content-addressed:

- `sha256` for binary identity and archive layout
- `md5` retained for BSim lookup compatibility

The manifest maps logical object identity to physical multipart archive membership.

## Database Model

### Local and test

For local validation, a file-backed BSim database can be created via:

- `file:/...` URL
- Ghidra `support/bsim`
- `bsim_db_tool.py`

This is suitable for smoke tests and local tooling checks.

### Shared / backend

For real backend use, the intended target is PostgreSQL-backed BSim:

- append collections over time
- query from RE tooling and a future MCP server
- avoid H2 locking limitations and single-process behavior

The long-term model is one shared queryable backend for multiple collections, not one separate database per small run.

Baseline-image corpora may still be published as milestone DB snapshots, but those are distribution artifacts, not the only backend model.

## Query Plane

Today, the repo supports:

- BSim DB creation
- signature import
- executable listing
- function listing

via:

- Ghidra `support/bsim`
- `build_bsim_db.sh`
- `bsim_db_tool.py`

Similarity querying is not yet wrapped here. That is expected to require either:

- a deeper Ghidra/BSim API integration
- or a future service layer that sits above the packaged corpus and DB

That future service is the likely base for the intended BSim MCP server.

## Current Workflow Inventory

### Smoke and validation

- `artifact-check.yml`
- `image-curation.yml`
- `index-refresh.yml`

### Legacy / existing pipeline

- `matrix-container.yml`
- `run-image.yml`

The newer workflows validate the v1 packaging and BSim corpus path. The image-curation workflow is the bounded baseline path intended for repeatable corpus collection from pinned Windows runner images. It now has two expected modes:

- a fast seed allowlist for quick validation
- a broader core allowlist for sharded corpus-building runs

The older workflows represent the original distributed download/decomp/scan flow.

## Current Proven Path

The following path has been proven in CI:

1. collect a bounded Windows runner subset
2. install pinned Ghidra
3. install latest `ghidrecomp`
4. generate BSim XML for a real system DLL
5. package binaries + BSim XML + manifest + toolchain lock
6. import the resulting XML into a local file-backed BSim DB
7. query executables and functions from that DB

This is the current operational baseline for the repo.
