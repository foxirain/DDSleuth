# Native Fast DDS probe

This executable is the public, non-exploit scenario driver for the Fast DDS adapter.
It creates a secure participant from the identity and signed policy artifacts injected
by the campaign runner and emits normalized `DDSLEUTH_EVENT` records.

## Build

```sh
cmake -S probes/fastdds_native -B build/fastdds-native
cmake --build build/fastdds-native -j
```

The build requires Fast DDS 3.x and Fast CDR 2.x CMake packages.

## Interface

```text
ddsleuth_fastdds_probe ACTOR MODE DOMAIN TOPIC TIMEOUT_MS EXPECTED [MESSAGE]
```

`MODE` is `writer`, `recreate-writer`, `reader`, `check-writer`, `check-reader`,
`scripted-writer`, `scripted-reader`, `observe-denied-writer`, or
`observe-denied-reader`; `EXPECTED` is `allow` or `deny`. Check modes stop after the
endpoint authorization decision. Observe-denied
modes keep an authenticated participant whose denied endpoint was rejected alive for
the configured timeout. Reader and writer modes emit `probe.ready` events and use DDS
callbacks and condition variables, not fixed sleeps.

Writers wait for one matched reader by default. Set `DDSLEUTH_EXPECTED_MATCHES` to a
positive integer for multi-recipient experiments; the sample is written only after
the live match count reaches that value. Readers wait for one sample by default;
`DDSLEUTH_EXPECTED_SAMPLES` raises that threshold. `recreate-writer` writes epoch 1,
deletes the endpoint, creates and rematches a new writer, then writes epoch 2.
`DDSLEUTH_HOLD_AFTER_WRITE_MS` keeps the writer participant alive after its final write,
allowing event-barrier-driven late-join and redistribution experiments without racing
process teardown.

`DDSLEUTH_SAMPLE_COUNT` makes a normal writer publish a numbered sample sequence.
`DDSLEUTH_MAX_BLOCKS_PER_SESSION` sets the Fast DDS endpoint property
`dds.sec.crypto.maxblockspersession`, allowing short, deterministic session-key
rotation campaigns when paired with `DDSLEUTH_EXPECTED_SAMPLES` on the reader.

Scripted modes consume the runner-generated `DDSLEUTH_ACTION_PLAN`. Writer plans
support `endpoint.create`, `endpoint.wait_match`, `sample.write`, and
`endpoint.destroy`; reader plans support `endpoint.create`, `sample.wait`, and
`endpoint.destroy`. Both modes support `participant.disconnect`,
`participant.reconnect`, and `credential.wait_revoked`. Disconnect requires the role
to destroy its endpoint first. Reconnect recreates the secure participant, type, topic,
publisher/subscriber, and later endpoint rather than merely emitting a lifecycle event.
`credential.wait_revoked` waits for a real unauthorized authentication callback.
An optional first argument overrides the match/sample/revocation target or
the written message as appropriate. The plan path is runner-reserved, its fields are
validated before launch, and every action is bracketed by `action.started` and
`action.completed` events. This makes endpoint lifecycle order and timing scenario
data rather than a growing collection of hard-coded probe modes.

Required environment variables are `DDSLEUTH_IDENTITY_CA`,
`DDSLEUTH_IDENTITY_CERTIFICATE`, `DDSLEUTH_IDENTITY_PRIVATE_KEY`, and
`DDSLEUTH_FASTDDS_POLICIES`. The campaign runner injects identity variables per role and
does not include private-key paths in evidence.

The probe deliberately contains no CryptoToken interception, raw packet injection,
key recovery, or vendor-private object access. Embargoed white-box capability modules
remain outside the public tree until coordinated disclosure permits release.
Transport actions are delegated to the separate loopback-only shim; the native probe
does not emulate wire replay with a second DDS write.
