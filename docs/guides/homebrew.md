# Homebrew

Install `px` and `px-server` on macOS or Linux with Homebrew. The formula builds
both binaries from a checksummed GitHub release source archive. It requires
network access to download the source and Go modules. Homebrew installs Go as a
build dependency; PX requires Go 1.26.4 or newer.

## Install

The tap lives in the `scotthaleen/px` repository, not a separate `homebrew-px`
repository. Use the explicit repository URL when adding it. These commands require
the formula to have been merged into the repository's default branch.

1. Add the tap:

   ```sh
   brew tap scotthaleen/px https://github.com/scotthaleen/px
   ```

2. Install both binaries:

   ```sh
   brew install scotthaleen/px/px
   ```

3. Test the installation with isolated state:

   ```sh
   brew test scotthaleen/px/px
   ```

The formula test runs `version` and `--help` for both binaries with a temporary
`PX_HOME`. It checks the release identity and confirms that these commands do not
create PX state.

Installation does not configure PX, enroll a device, select a default server, or
start an agent or server. No Homebrew service is registered. To configure PX
explicitly after installation, follow [Onboarding](onboarding.md). To host a
rendezvous server, see [Secure Rendezvous](secure-rendezvous.md).

## Upgrade Or Remove

To install a newer version after the tap formula has been updated:

```sh
brew update
brew upgrade scotthaleen/px/px
brew test scotthaleen/px/px
```

To remove the binaries and tap:

```sh
brew uninstall scotthaleen/px/px
brew untap scotthaleen/px
```

Uninstalling does not delete existing PX state or stop processes that you started
separately. Stop those processes before uninstalling if they are no longer needed.

## Maintain The Formula

Update `Formula/px.rb` after each [published release](releasing.md). The release
workflow does not update the formula automatically. Homebrew users remain on the
formula's pinned release until this update is merged.

1. Inspect the published tag and resolve its exact commit:

   ```sh
   gh release view --repo scotthaleen/px --json tagName,url
   gh api repos/scotthaleen/px/commits/TAG --jq .sha
   ```

   Replace `TAG` with the published CalVer tag, including any same-day suffix.

2. Download and hash the source archive from the repository root:

   ```sh
   mkdir -p dist
   curl --fail --location --output dist/px-source.tar.gz \
     https://github.com/scotthaleen/px/archive/refs/tags/TAG.tar.gz
   shasum -a 256 dist/px-source.tar.gz
   ```

   Use the checksum of this source archive, not a platform binary archive or its
   entry in the release's `SHA256SUMS` file. Do not guess checksum values.

3. Update the formula's source URL, SHA-256, and full commit in both the build
   flags and test assertion. The version is derived from the URL. The build embeds
   that CalVer version, the pinned commit, and the actual UTC source-build time.
   Check the release's `go.mod` minimum against Homebrew's Go dependency.

4. Validate the updated formula in a local tap checkout:

   ```sh
   brew style scotthaleen/px/px
   brew audit --strict --online scotthaleen/px/px
   brew reinstall --build-from-source scotthaleen/px/px
   brew test scotthaleen/px/px
   ```

   Use `brew install --build-from-source` instead of `brew reinstall` if PX is not
   installed. Run the install and test on both macOS and Linux before claiming
   validation on both platforms. The formula test checks CLI startup, not network
   transfers or enrollment.
