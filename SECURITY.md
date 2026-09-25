# Security and coordinated disclosure

## Supported versions

The latest `0.1.0` alpha pre-release is supported. Earlier development snapshots are
not maintained.

## Framework vulnerabilities

Do not open a public issue for a vulnerability in DDSleuth that could expose secrets,
escape its local execution boundary, or cause it to contact unintended systems.
Contact a maintainer privately using the contact information on their GitHub profile,
and do not include exploit details or an unpatched reproducer in a public issue.

## Vulnerabilities discovered in DDS implementations

The framework is intended for authorized local research. Findings in a DDS implementation must be disclosed to the affected vendor or project before publishing a trigger, key-recovery method, packet-forgery module, or reproducible exploit chain.

Public regression cases should contain only information that is already public, has been fixed, or has been approved for release by the affected maintainer. Embargoed cases belong outside the public repository.

## Execution boundary

Checked-in scenarios must use loopback or a disposable isolated network. External or production targets require explicit authorization and are not enabled by the default runner.

The current process runner isolates protocol roles logically, not as mutually hostile
operating-system users. Generated private keys are mode `0600` and only the matching
key path is injected into each role, but all roles normally execute under the same OS
account. A probe executable is therefore trusted harness code and must not attempt to
read another role's run directory. Container/user-namespace isolation is required
before treating a role as hostile local code.
