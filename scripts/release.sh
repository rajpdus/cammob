#!/bin/zsh
# Usage: scripts/release.sh 0.1.0
# Stamps the version into Info.plist, builds the bundle, zips it and writes SHA256SUMS.txt.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${1:?version required, e.g. 0.1.0}
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" scripts/Info.plist
BUILD_NUM=$(git rev-list --count HEAD 2>/dev/null || echo 1)
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUM" scripts/Info.plist
./scripts/bundle.sh
ZIP="build/CamMob-$VERSION.zip"
rm -f "$ZIP"
ditto -c -k --keepParent build/CamMob.app "$ZIP"
(cd build && shasum -a 256 "CamMob-$VERSION.zip" > SHA256SUMS.txt && cat SHA256SUMS.txt)
