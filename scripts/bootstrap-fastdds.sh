#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
destination=${1:-"$repo_root/.deps/Fast-DDS-f6376882"}
expected_revision=f6376882050013616d1b0aeacaca2ccc9ee06874

if [[ -e "$destination" ]]; then
    printf 'destination already exists: %s\n' "$destination" >&2
    exit 1
fi

mkdir -p "$(dirname -- "$destination")"
git clone --filter=blob:none https://github.com/eProsima/Fast-DDS.git "$destination"
git -C "$destination" checkout --detach "$expected_revision"
"$repo_root/scripts/prepare-fastdds-observer.sh" "$destination"

printf 'Prepared instrumented Fast DDS source at %s\n' "$destination"
