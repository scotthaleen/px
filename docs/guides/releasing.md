# GitHub Releases

Maintainers publish releases with the `Release` GitHub Actions workflow. No source version bump is required.

1. Merge the intended changes into `master` and inspect CI results.
2. Open **Actions > Release > Run workflow** and select `master`.
3. Wait for verification, packaging, and publication to finish.
4. Inspect the new entry on the repository's Releases page.

The workflow verifies the exact dispatch commit again. It runs the full Linux Task gate and native macOS/Windows fast gates before packaging. Builds use Go 1.26.6 and Task 3.44.1. Test state uses the isolated `PX_HOME` configured by Task.

Release versions use UTC `YYYY.MM.DD`. Additional releases on the same date use `.1`, `.2`, and so on. A single release concurrency group serializes publication. Each build embeds the resolved version, full commit ID, and one UTC timestamp. Release tags have the same name as the version, without a `v` prefix.

The workflow attaches public `install.sh` and `install.ps1` scripts, six archives, and `SHA256SUMS`. Linux and macOS archives use `.tar.gz`; Windows archives use `.zip`. Each platform has amd64 and arm64 builds, and each archive includes `px`, `px-server`, the release manifest, license, and notices. Checksums cover both installers and all archives. Builds have no deployment-specific rendezvous default. No private installer or local deployment artifact is uploaded.

After publication, update the in-repository [Homebrew formula](homebrew.md#maintain-the-formula) to the new source tag, source checksum, and commit. This is a separate source commit, not an edit to published release assets.

All platforms are cross-built on Linux. Linux amd64 packaged executables are also run before upload. Native CI is not equivalent to executing every release archive: Windows arm64 and the remaining architecture combinations still need the native validation campaign. Binaries are not OS-code-signed or notarized; checksums are integrity checks, not independent publisher authentication.

The publish job creates a new tag and uploads assets to a draft before making it public. It never moves tags or overwrites existing release assets. If publication fails after tag creation, inspect the draft and tag before recovery. A new dispatch selects a new version; do not overwrite a published version to repair it. Verification failure creates no release tag.

Repository maintainers should enable GitHub release immutability and protect `master`. The workflow itself refuses tag reuse, but does not configure repository protection settings. GitHub's built-in token supplies publication access; no personal access token or external release provider is required.
