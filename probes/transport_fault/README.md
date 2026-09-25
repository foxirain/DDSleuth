# Loopback transport fault shim

This opt-in `LD_PRELOAD` shim applies authenticated DDSleuth action plans at the
UDP syscall boundary. It only mutates datagrams addressed to IPv4 loopback or
IPv6 `::1`; other destinations pass through unchanged.

Supported actions are `transport.drop_next [count]`,
`transport.delay_next DELAY_MS`, `transport.duplicate_next [count]`, and
`transport.replay_last [count]`. Replay sends the exact previously captured
wire datagram rather than issuing a new DDS write. The clock starts at the
role's first intercepted datagram. Every armed or applied fault emits a
normalized `DDSLEUTH_EVENT`.

Build the shared object and pass its absolute path as
`DDSLEUTH_TRANSPORT_FAULT_LIBRARY`. The runner injects it only into roles whose
scenario action list contains a `transport.*` operation and only when the
scenario network is `loopback`.

If the target executable is sanitizer-instrumented and its runtime requires the
first preload slot, supply that runtime in `LD_PRELOAD`; DDSleuth preserves the
existing order and appends the fault shim.
