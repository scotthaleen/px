# ADR-0005: Use CalVer Versioning with Build Metadata

Status: Accepted

Date: 2026-07-27

## Context

PX needs a versioning scheme for local builds and installed binaries. It is an experimental private or internal CLI, so SemVer compatibility signaling is less useful than knowing when a binary was built and from which commit.

## Considered Options

- SemVer with Git tags requires manual tags or release automation and implies compatibility guarantees the project is not ready to make.
- CalVer from the build date derives `YYYY.MM.DD` automatically and answers when the binary was built.
- A raw Git commit is precise but not human-friendly as the primary version.

## Decision

Use CalVer in `YYYY.MM.DD` format from the UTC build date, derived at build time through Taskfile ldflags, with the commit hash and RFC 3339 UTC build timestamp embedded alongside it.

CalVer and build metadata do not define protocol compatibility. Independently
versioned wire protocols are the compatibility boundary; builds with different
dates remain compatible when they implement the same protocol versions.

## Consequences

- Add `internal/versioninfo` with `Version`, `Commit`, and `Date` variables set by ldflags.
- Add a `version` command that prints the complete build identity.
- Taskfile owns build metadata derivation.
- The commit hash disambiguates multiple builds from the same day.
- Normal local builds do not require Git tags.
