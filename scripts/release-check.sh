#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
python_bin=${DDSLEUTH_PYTHON:-python3}
artifact_dir="$repo_root/.release/dist"
install_root=$(mktemp -d "${TMPDIR:-/tmp}/ddsleuth-install.XXXXXX")

cleanup()
{
    rm -rf -- "$install_root"
}
trap cleanup EXIT

DDSLEUTH_REQUIRE_NATIVE_TESTS=1 "$repo_root/scripts/test.sh"
"$repo_root/scripts/run-smoke.sh"
"$python_bin" "$repo_root/scripts/check_release.py"

if ! "$python_bin" -c 'import build, setuptools, twine, wheel' 2>/dev/null; then
    printf 'release or build-backend dependencies are missing; install with: python -m pip install ".[release]"\n' >&2
    exit 1
fi

rm -rf -- "$artifact_dir"
mkdir -p "$artifact_dir"
"$python_bin" -m build --no-isolation --sdist --outdir "$artifact_dir" "$repo_root"

source_archive=$(find "$artifact_dir" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)
"$python_bin" "$repo_root/scripts/verify_artifacts.py" "$artifact_dir" --sdist-only
mkdir -p "$install_root/source"
tar -xzf "$source_archive" -C "$install_root/source"
source_root=$(find "$install_root/source" -mindepth 1 -maxdepth 1 -type d -print -quit)
if [[ -z "$source_root" ]]; then
    printf 'source archive did not contain a top-level directory\n' >&2
    exit 1
fi
"$python_bin" -m build --no-isolation --wheel --outdir "$artifact_dir" "$source_root"

"$python_bin" -m twine check "$artifact_dir"/*
"$python_bin" "$repo_root/scripts/verify_artifacts.py" "$artifact_dir"

"$python_bin" -m venv "$install_root/venv"
wheel_path=$(find "$artifact_dir" -maxdepth 1 -type f -name '*.whl' -print -quit)
"$install_root/venv/bin/python" -m pip install --no-index --no-deps "$wheel_path"
"$install_root/venv/bin/ddsleuth" --version
"$install_root/venv/bin/ddsleuth" validate \
    "$repo_root/examples/fastdds/three_party_recipient_binding.json"

printf 'DDSleuth release checks passed. Artifacts: %s\n' "$artifact_dir"
