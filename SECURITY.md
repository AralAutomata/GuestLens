# Security Policy

## Supported scope

Security reports are welcome for:

- local dashboard exposure beyond `127.0.0.1`
- unsafe report export behavior
- advisory bundle validation flaws
- privilege or path handling in the collector/runtime directories
- data exposure across trust boundaries that contradicts the documented product contract

## Not in scope

- findings that describe unsupported host-only guarantees
- stale or incomplete sample advisory data
- issues that require cloud, fleet, or remote multi-user features that do not exist in this phase

## Reporting

Please report vulnerabilities privately through your repository security contact or GitHub security advisories once the public repo is live. Include:

- affected version or commit
- guest distro and version
- reproduction steps
- impact assessment

Avoid filing undisclosed vulnerabilities as public issues.
