# Loopback transport fault shim

This opt-in `LD_PRELOAD` shim applies authenticated DDSleuth action plans at the
UDP syscall boundary. It only mutates datagrams addressed to IPv4 loopback or
IPv6 `::1`; other destinations pass through unchanged.

Supported actions are `transport.drop_next [count]`,
`transport.delay_next DELAY_MS`, `transport.duplicate_next [count]`, and
`transport.capture_next [count]`, followed by `transport.replay_last [count]`.
Capture records without mutating delivery. Replay prefers the explicitly captured
datagram and otherwise falls back to the latest datagram. It sends the exact captured
wire datagram rather than issuing a new DDS write. Every armed or applied fault emits
an action-id-correlated normalized `DDSLEUTH_EVENT` with a monotonic timestamp.

Generic executables use the action-plan clock. The Fast DDS native probe sets
`DDSLEUTH_TRANSPORT_CONTROL=explicit` and calls the shim control symbol at the exact
action boundary; this makes `duplicate_next` followed by `sample.write` a synchronous
ordering constraint rather than two racing timers.

Build the shared object and pass its absolute path as
`DDSLEUTH_TRANSPORT_FAULT_LIBRARY`. The runner injects it only into roles whose
scenario action list contains a `transport.*` operation and only when the
scenario network is `loopback`. The runner rejects a completed trial when any requested
fault lacks its correlated applied event or reports a failed outcome.

If the target executable is sanitizer-instrumented and its runtime requires the
first preload slot, supply that runtime in `LD_PRELOAD`; DDSleuth preserves the
existing order and appends the fault shim.
