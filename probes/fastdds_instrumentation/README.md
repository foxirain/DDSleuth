# Fast DDS white-box observer

This opt-in observer records endpoint CryptoToken routing and run-local key-material
fingerprints at the `SecurityManager` boundary. It never persists a key, certificate
private material, or a stable cross-run fingerprint. The runner supplies one ephemeral
HMAC secret to all processes in a case so equal material can be compared only inside
that case.

The observer is intentionally a source overlay rather than a replacement crypto
plugin. That keeps the protocol path, access-control decisions, key factory, and wire
encoding under test unchanged. `fastdds-f6376882-ddsleuth-observer.patch` adds six
CryptoToken observation calls—both normal discovery and redistribution paths for
outbound DataWriter/DataReader token creation, plus inbound addressed
DataWriter/DataReader token dispatch—one session-rotation observation in the
serialized-payload transform, and lifecycle observations around identity invalidation
and successful participant master-key regeneration. Rotation evidence contains
session identifiers, cause, and configured block threshold, never a session or master
key. Revocation is still triggered by Fast DDS's certificate-expiry machinery; the
observer does not provide a synthetic revoke control path.

The supported source revision is exactly
[`f6376882050013616d1b0aeacaca2ccc9ee06874`](https://github.com/eProsima/Fast-DDS/commit/f6376882050013616d1b0aeacaca2ccc9ee06874)
(its package metadata reports 3.6.2).
Prepare it with `scripts/bootstrap-fastdds.sh`, or apply the overlay to an existing
clean checkout with:

```sh
scripts/prepare-fastdds-observer.sh /path/to/Fast-DDS
```

Make these directories visible to the Fast DDS C++ compiler:

```text
probes/common
probes/fastdds_instrumentation
```

Enable observations only for controlled experiments with
`DDSLEUTH_FASTDDS_OBSERVER=1`. The framework injects `DDSLEUTH_ACTOR` and the run-local
fingerprint secret. If instrumentation fails, it emits `probe.observer_error` and does
not alter the protocol return value. Scenarios using this observer should include the
`observer_health` assertion so missing evidence or an observer exception makes the run
inconclusive rather than passing silently.

The patch is version-pinned and must fail to apply when its source context changes.
Treat a failed application as a request to review the new Fast DDS security path, not
as a reason to use a fuzzy patch.
