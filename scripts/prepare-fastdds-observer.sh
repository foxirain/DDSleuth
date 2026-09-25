#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s FAST_DDS_SOURCE\n' "$0" >&2
    exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fastdds_source=$(cd -- "$1" && pwd)
expected_revision=f6376882050013616d1b0aeacaca2ccc9ee06874
observer_patch="$repo_root/probes/fastdds_instrumentation/fastdds-f6376882-ddsleuth-observer.patch"
actual_revision=$(git -C "$fastdds_source" rev-parse HEAD)

if [[ "$actual_revision" != "$expected_revision" ]]; then
    printf 'unsupported Fast DDS revision: expected %s, got %s\n' \
        "$expected_revision" "$actual_revision" >&2
    exit 1
fi
if ! git -C "$fastdds_source" diff --quiet --ignore-submodules -- || \
        ! git -C "$fastdds_source" diff --cached --quiet --ignore-submodules --; then
    printf 'Fast DDS checkout must be clean before applying the observer patch\n' >&2
    exit 1
fi

git -C "$fastdds_source" apply --check "$observer_patch"
git -C "$fastdds_source" apply "$observer_patch"

printf 'Applied the DDSleuth observer to Fast DDS %s.\n' "$expected_revision"
printf 'Add these include directories to the Fast DDS compiler invocation:\n'
printf '  %s/probes/common\n' "$repo_root"
printf '  %s/probes/fastdds_instrumentation\n' "$repo_root"
