# Misaka versioning

Misaka's main Rust distribution uses Calendar Versioning (CalVer):

```text
YYYY.M.D
```

`YYYY` is the release year, `M` is the release month, and `D` is the
release day. They are calendar fields, not major/minor/patch compatibility
levels. Components other than the four-digit year do not have leading zeroes.
For example, `2026.9.18`, `2026.10.3`, and `2027.1.6` are valid forms.

The first intended dogfooding release is `2026.9.18`, represented by the Git
tag `v2026.9.18`. A published CalVer tag and its release artifacts are
immutable: a failed infrastructure-only workflow may be rerun on the same
tagged commit, but a successful release tag is never force-moved and its
artifacts are never overwritten. The initial policy is one normal formal
release per calendar date; no same-day revision suffix is defined yet.

## Release identity and exact build identity

The release identity is the package version, such as `2026.9.18`. The exact
build identity is that version together with `MISAKA_BUILD_GIT_SHA`, reported
by `misaka version --json` as `build_git_sha`. Development builds may
continue to report the latest package CalVer while carrying a different Git
SHA. Cargo does not receive a date-version change on every commit.

CalVer expresses release time, not compatibility guarantees. It does not mean
that all releases in a year are wire-compatible, that a later date is always
compatible, or that two builds from the same date are identical.

## Compatibility boundaries

CalVer is binary/release metadata only. It is deliberately independent from
all protocol and persistent-schema versions:

| Concern | Version identity |
| --- | --- |
| Misaka binary release | CalVer `YYYY.M.D` |
| Exact build | CalVer plus Git SHA |
| Persistent state layout | integer, currently layout `1` |
| Gateway protocol | independent integer |
| Authenticated session | independent protocol version |
| NetworkStream | independent protocol version |
| Enrollment | independent protocol version |
| Other wire/schema contracts | independent protocol or schema versions |

Changing `2026.9.18` to `2026.10.3` does not itself require a state
migration. Only a real persistent-schema change advances the state-layout
version. Two Sisters with different binary dates may communicate when their
relevant protocol and schema versions remain compatible. Compatibility is
checked at those protocol/state boundaries, never inferred from the CalVer
date.

The project remains **Pre-Resource Alpha**. The current engineering focus is
real installation, long-running per-user deployment, and multi-machine
dogfooding; Resource/Ability abstractions are not part of this release.
