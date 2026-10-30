#!/usr/bin/env bash
# ci/notarize_release.sh — notarize and staple the Developer ID release build.
#
# Requires the self-hosted macOS runner to hold:
#   - a "Developer ID Application" identity in its keychain, and
#   - a notarytool keychain profile, by default `casa1-notary`:
#       xcrun notarytool store-credentials casa1-notary \
#         --apple-id <id> --team-id <team> --password <app-specific-password>
#     Override the profile name with CASA1_NOTARYTOOL_PROFILE (wired through the
#     workflow as `vars.CASA1_NOTARYTOOL_PROFILE`).
#
# Why an .app bundle is notarized instead of each bare binary:
#   `xcrun stapler staple` accepts app bundles, disk images, installer packages
#   and XIP archives — it does NOT accept bare Mach-O executables or ZIP files.
#   The release binaries are packaged into a signed Casa1.app bundle, the bundle
#   is submitted with `notarytool submit --wait`, and the resulting ticket is
#   stapled to the bundle. The bare binaries remain the artifacts the E2E and
#   smoke jobs execute; they carry the same Developer ID signatures that the
#   notary service recorded for the bundle contents.
#
# Usage:
#   SIGNING_MODE=developer-id NOTARYTOOL_PROFILE=casa1-notary \
#     ./ci/notarize_release.sh

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${SIGNING_MODE:-}" != "developer-id" ]]; then
  echo "::warning::skipping notarization: SIGNING_MODE=${SIGNING_MODE:-unknown} (ad-hoc builds are non-release evidence only)" >&2
  exit 0
fi

PROFILE="${NOTARYTOOL_PROFILE:-casa1-notary}"
if [[ -z "$PROFILE" ]]; then
  echo "::error::NOTARYTOOL_PROFILE is empty; configure a notarytool keychain profile" >&2
  exit 1
fi

BINS=(casa1 macwin casa1-runner casa1-helper casa1-test-guest casa1-oracle)
for b in "${BINS[@]}"; do
  if [[ ! -f "target/release/$b" ]]; then
    echo "::error::missing signed release binary target/release/$b" >&2
    exit 1
  fi
done

IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | awk '/Developer ID Application/ {print $2; exit}')"
if [[ -z "$IDENTITY" ]]; then
  echo "::error::no 'Developer ID Application' identity available for the app bundle signature" >&2
  exit 1
fi

STAGE="$(mktemp -d "${RUNNER_TEMP:-/tmp}/casa1-notarize.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

APP="$STAGE/Casa1.app"
mkdir -p "$APP/Contents/MacOS"
for b in "${BINS[@]}"; do
  cp "target/release/$b" "$APP/Contents/MacOS/$b"
done

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>casa1-runner</string>
  <key>CFBundleIdentifier</key>
  <string>com.casa1.release</string>
  <key>CFBundleName</key>
  <string>Casa1</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>0.1.0</string>
</dict>
</plist>
PLIST

/usr/bin/codesign --force --deep --sign "$IDENTITY" --options runtime "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"

ZIP="$STAGE/Casa1.zip"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"

echo "Submitting $ZIP to the Apple notary service (profile: $PROFILE) ..."
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait

echo "Stapling notarization ticket to $APP ..."
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

rm -rf target/release/Casa1.app
cp -R "$APP" target/release/Casa1.app
echo "Notarized and stapled bundle: target/release/Casa1.app"
