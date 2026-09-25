# Architecture

## Design goal

DDSleuth separates the question *what security property should hold?* from *how does this DDS implementation expose enough evidence to test it?*

```text
Scenario
   |
   v
Process runner -----> Implementation adapter
   |                         |
   |                         v
   +-----------------> Normalized events
                              |
                              v
                    Invariant and capability engine
                              |
                              v
                    Reproducible evidence report
```

## Scenario layer

A scenario declares actors, policy intent, protected resources, implementation configuration, process roles, and assertions. It does not contain an oracle implementation or vendor-private object layout.

`policy.grant_order` is explicit because grant selection order can be security-relevant
when certificate subjects collide or overlap. Object insertion order and JSON
serialization order are never used as a hidden policy input; grant order can be varied
directly as a matrix dimension.

## Adapter layer

An adapter is responsible for launching or attaching to one DDS implementation and translating its observations into normalized events. White-box adapters may instrument a security plugin or implementation internals. Black-box adapters may use RTPS capture, a controlled participant, and application callbacks.

The first adapter imports the existing Fast DDS harness logs. This importer is a migration boundary, not the final instrumentation protocol. Native probes emit normalized JSON events through `probes/common/ddsleuth_event.hpp`.

Native scenarios may declare `start_after` event barriers on a role. The runner tails
structured events from already-started roles and starts the dependent role only after
the required actor, event kind, outcome, and optional attributes are observed. A source
process that exits early or a barrier timeout is an infrastructure error, not a passing
security result.

## Evidence layer

Events record concrete observations, not conclusions. Examples include:

- endpoint creation denied by access control;
- CryptoToken plaintext observed by a participant;
- inner token destination differs from the observing participant;
- sender or receiver-specific key material is present;
- legitimate protected traffic was decrypted;
- forged protected traffic was accepted;
- attacker-controlled data reached an application reader.

Secret key bytes are never required in the normalized evidence format.

## Oracle layer

Oracles evaluate one invariant against a scenario and its events. They return `pass`, `violation`, or `not_applicable`, together with the exact event indexes supporting the result. Capability assessment is separate from root-cause classification so that an unexpected token is not automatically described as an integrity or availability compromise.

Instrumentation health is itself an invariant. An enabled observer must emit its
required evidence and no observer-error event; otherwise the affected run is
inconclusive. Lifecycle oracles consume explicit endpoint destruction boundaries and
monotonic cross-process ordering rather than inferring epochs from filenames or sleeps.

## Campaign layer

The matrix engine mutates declared scenario fields and records every assignment and
scenario digest in a manifest. The campaign runner verifies those digests, executes one
case at a time, preserves evidence per case, and aggregates pass, violation,
inconclusive, and infrastructure-error counts. Process failures and harness errors are
never converted into passing security assertions. Sequential execution is the safe
default until a scheduler can prove domain and transport isolation between cases.
Policy mutations are fail-closed: campaign execution requires per-case policy
materialization, records the exact artifact hashes and signing-certificate hash in the
evidence bundle, and injects that directory into the adapter. External policies may be
used only through an explicit diagnostic override and are labelled unverified.

Every launched role records the basename, size, and SHA-256 of its resolved executable
in the evidence metadata. Absolute host paths are intentionally omitted. Policy,
identity-certificate, scenario, and executable digests together form the minimum
configuration provenance needed to compare or reproduce a campaign result.

## Fast DDS first

Fast DDS is the initial implementation adapter because the golden experiment already covers signed policies, three independent identities, endpoint matching, volatile-secure token delivery, AES-GCM-GMAC key material, raw UDP, RTPS parsing, and application delivery. The core must not import Fast DDS headers or depend on Fast DDS GUID layouts.

## Portability boundary

Future Cyclone DDS, OpenDDS, and Connext adapters must emit the same normalized event types. A scenario should require only adapter configuration changes when it is portable across implementations.
