## Change

Describe the security invariant, adapter behavior, or framework contract changed.

## Evidence

- [ ] Tests cover the behavior change.
- [ ] Missing evidence still produces an inconclusive result, not a pass.
- [ ] No private key, raw key material, credential, stable fingerprint, or embargoed
      vulnerability detail is included.
- [ ] Implementation-specific code remains behind an adapter or instrumentation
      boundary.
- [ ] `scripts/test.sh` passes.
- [ ] `scripts/release-check.sh` passes when the change affects a release artifact.

Do not attach an unpatched exploit or undisclosed vendor finding to a public pull
request. Follow `SECURITY.md` instead.
