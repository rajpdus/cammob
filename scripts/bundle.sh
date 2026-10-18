#!/bin/zsh
# Build a release binary and wrap it in CamMob.app.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH=/opt/homebrew/bin:$PATH
swift build -c release --product CamMob 2>&1 | tail -3
APP=build/CamMob.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/CamMob "$APP/Contents/MacOS/CamMob"
cp scripts/Info.plist "$APP/Contents/Info.plist"
[ -f Resources/AppIcon.icns ] && cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
codesign --force --deep --sign - "$APP"
echo "Built $APP"
