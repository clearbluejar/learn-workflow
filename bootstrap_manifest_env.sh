#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv-gen"
PYTHON_BIN="${VENV_DIR}/bin/python"
DATA_DIR="${VENV_DIR}/lib/python3.14/site-packages/cvedata/data"
TMP_DIR="${ROOT_DIR}/collections_build/bootstrap"

mkdir -p "${TMP_DIR}"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  uv venv "${VENV_DIR}"
fi

uv pip install --python "${PYTHON_BIN}" -r "${ROOT_DIR}/gen-requirements.txt" pandas

mkdir -p "${DATA_DIR}"
rm -f "${TMP_DIR}/cvedata_data.zip"
gh release download -R clearbluejar/cvedata -p cvedata_data.zip -D "${TMP_DIR}" --clobber
unzip -oq "${TMP_DIR}/cvedata_data.zip" -d "${DATA_DIR}"

echo "Manifest environment ready at ${VENV_DIR}"
echo "cvedata data extracted into ${DATA_DIR}"
