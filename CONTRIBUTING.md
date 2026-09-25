# Contributing

Thank you for improving DDSleuth. Contributions should preserve the separation
between portable security invariants and implementation-specific observation code.

## Development setup

Python 3.11 or newer is required. The core has no runtime dependency outside the
standard library; native and policy tests additionally use a C++17 compiler and
OpenSSL.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --editable .
./scripts/test.sh
```

Use `./scripts/bootstrap-fastdds.sh` to prepare the exact supported Fast DDS source
revision with the observer overlay. It does not install Fast DDS or Fast CDR build
dependencies. `./scripts/run-smoke.sh` exercises the dependency-free core plus OpenSSL
identity and signed-policy materialization.

## Change requirements

- Add tests for behavior changes and new oracles.
- Treat missing evidence and instrumentation failures as inconclusive, never pass.
- Keep raw keys, private certificates, stable key fingerprints, and credentials out of
  evidence and logs.
- Keep vendor-private types behind an adapter or opt-in instrumentation boundary.
- Use explicit event barriers for cross-process coordination; do not add timing-only
  sleeps as causal evidence.
- Document the supported implementation revision for every source overlay.

Run `./scripts/release-check.sh` before proposing a release-affecting change.
The release gate additionally requires:

```sh
python -m pip install --editable '.[release]'
```

## Security research and disclosure

Do not submit an unpatched implementation vulnerability, exploit trigger, recovered
key, or embargoed report in a public pull request or issue. Follow `SECURITY.md` and
coordinate with the affected implementation maintainer first.

## Licensing

Unless explicitly stated otherwise, contributions are accepted under Apache-2.0, the
license of this repository. By submitting a contribution, you represent that you have
the right to license it on those terms.
