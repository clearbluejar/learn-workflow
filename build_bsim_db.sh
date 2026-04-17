#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <ghidra_install_dir> <bsim_db_url> <bsim_xml_dir> [ghidra_namespace]" >&2
  exit 1
fi

GHIDRA_INSTALL_DIR=$1
BSIM_DB_URL=$2
BSIM_XML_DIR=$3
GHIDRA_NAMESPACE=${4:-}

BSIM_BIN="${GHIDRA_INSTALL_DIR}/support/bsim"

if [[ ! -x "${BSIM_BIN}" ]]; then
  echo "Missing bsim utility: ${BSIM_BIN}" >&2
  exit 1
fi

if [[ ! -d "${BSIM_XML_DIR}" ]]; then
  echo "Missing BSim XML directory: ${BSIM_XML_DIR}" >&2
  exit 1
fi

override_args=()
if [[ -n "${GHIDRA_NAMESPACE}" ]]; then
  override_args=(--override "${GHIDRA_NAMESPACE}")
fi

echo "Importing BSim XML from ${BSIM_XML_DIR} into ${BSIM_DB_URL}"
"${BSIM_BIN}" commitsigs "${BSIM_DB_URL}" "${BSIM_XML_DIR}" "${override_args[@]}"

