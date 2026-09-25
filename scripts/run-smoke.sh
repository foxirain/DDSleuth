#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
python_bin=${DDSLEUTH_PYTHON:-python3}
smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/ddsleuth-smoke.XXXXXX")

cleanup()
{
    rm -rf -- "$smoke_root"
}
trap cleanup EXIT

export PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}"
scenario="$repo_root/examples/fastdds/three_party_recipient_binding.json"

"$python_bin" -m ddsleuth --version
"$python_bin" -m ddsleuth validate "$scenario"
"$python_bin" -m ddsleuth materialize-identities \
    "$scenario" \
    --output-dir "$smoke_root/identities"
"$python_bin" -m ddsleuth materialize-policies \
    "$scenario" \
    --output-dir "$smoke_root/policies" \
    --subject 'mallory=O=DDSleuth,CN=mallory' \
    --subject 'bob=O=DDSleuth,CN=bob' \
    --subject 'alice=O=DDSleuth,CN=alice' \
    --signer-cert "$smoke_root/identities/identity-ca.cert.pem" \
    --signer-key "$smoke_root/identities/identity-ca.key"
"$python_bin" -m ddsleuth expand-matrix \
    "$scenario" \
    --output-dir "$smoke_root/matrix" \
    --strategy pairwise \
    --dimension 'governance.rtps_protection=["sign","encrypt"]' \
    --dimension 'topics.SecretTopic.metadata_protection=["sign","encrypt_with_origin_authentication"]'

printf 'DDSleuth core smoke test passed.\n'
