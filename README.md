<p align="center">
  <img src="docs/icon.png" width="128" alt="CamMob icon">
</p>

<h1 align="center">CamMob</h1>

<p align="center">
  A native macOS client for CP Plus DVRs / NVRs that are normally viewed with the
  <b>gCMOB</b> / <b>iCMOB</b> phone apps.<br>
  Add the recorder by its P2P serial number (scan the QR), and watch the channels live.
</p>

<p align="center">
  <a href="https://github.com/rajpdus/cammob/releases"><img src="https://img.shields.io/github/v/release/rajpdus/cammob?label=release" alt="release"></a>
  <img src="https://img.shields.io/badge/macOS-14%2B-blue" alt="macOS 14+">
  <img src="https://img.shields.io/badge/Apple%20Silicon-arm64-black" alt="arm64">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

CamMob reaches the recorder the same way the phone apps do: through CP Plus's
**InstaOn** P2P cloud (an Easy4ip-protocol service), so it works behind carrier-grade
NAT with no port forwarding, DDNS or VPN. Video is pulled over RTSP inside the P2P
tunnel and decoded in hardware. Nothing but the serial number and the device login is
needed; the password stays in your login Keychain.

Because the app is signed ad hoc (no Apple Developer ID), macOS treats each update as a
new program and asks once whether CamMob may read the password from your Keychain.
Click **Always Allow** and the window appears.

## Install

```sh
brew tap rajpdus/tap
brew install --cask cammob
```

Or download `CamMob-<version>.zip` from the [releases page](https://github.com/rajpdus/cammob/releases),
unzip, and drag `CamMob.app` to Applications. The app is ad-hoc signed, so on first launch
right-click → Open (or `xattr -dr com.apple.quarantine CamMob.app`).

Requires macOS 14 (Sonoma) or later on Apple Silicon.

## Use

1. Press **⌘N** (or the **+** button) to add a recorder.
2. **Scan QR**: hold the DVR's QR sticker, or the code shown under its *Network → P2P*
   menu, up to the Mac's camera. A photo dropped onto the sheet, an image file, or the
   clipboard works too. A gCMOB *device card* QR (Device Manager → export) fills in the
   name, user, password and channel count as well.
3. Enter the device username / password, then **Add**. On the first connection CamMob
   asks the recorder which channels have a camera and uses the recorder's channel names;
   the channel count in the sheet is only used until then.
4. Select the device in the sidebar. Each channel tile shows its state; click a tile to
   view it full size and click again to go back. **SD / HD** in the toolbar switches every
   channel between the recorder's sub stream and main stream. The list icon opens the
   protocol log.

Sub stream is used by default to keep bandwidth low; switch a device to main stream
from its Edit sheet.

## Command-line tool

`camtool` exercises the same library without the UI:

```sh
swift run camtool probe  <SERIAL>                              # cloud lookup, device ports
swift run camtool stream <SERIAL> -u admin -c 1 -s 1 -n 100 -o ch1.h265   # save raw frames
swift run camtool tunnel <SERIAL> -u admin -l 1554             # expose the DVR's RTSP locally
swift run camtool channels <SERIAL> -u admin                     # channel list and names from the recorder
ffplay -rtsp_transport tcp "rtsp://admin:PASS@127.0.0.1:1554/cam/realmonitor?channel=1&subtype=1"
swift run camtool qr photo.jpg                                 # decode a device QR
```

The password can be passed with `-p` or the `CAM_PASSWORD` environment variable.
`-C instaon|easy4ip` pins the cloud (both are tried by default), `-m direct` forces a
hole punch, `-v` prints every cloud request.

## Build from source

```sh
git clone https://github.com/rajpdus/cammob && cd cammob
swift build && swift run CamMob      # debug build
swift test                           # protocol unit tests
scripts/bundle.sh                    # build/CamMob.app
```

Xcode 16+ / Swift 6 toolchain. No third-party dependencies.

## How it works

| Target | Role |
|---|---|
| `DahuaP2P` | UDP socket, DH-HTTP cloud protocol (WSSE), device crypto, reliable PTCP session, relay/direct handshake, tunnel realms |
| `DahuaRTSP` | RTSP client over a realm, RTP H.264/H.265 depacketizer to Annex B |
| `CamMob` | SwiftUI app: device list, QR scanning (Vision), live grid on `AVSampleBufferDisplayLayer` |
| `camtool` | CLI harness |

The handshake, in short: the InstaOn main server resolves the serial to a P2P server and a
relay; the P2P server returns the device's encrypted info (ports and the password salt);
a `p2p-channel` request signed with HMAC-SHA256 of `MD5("user:Login to <salt>:pass")`
makes the device announce its NAT address; the device is told to join a relay agent;
PTCP (Dahua's reliable stream over UDP) runs through the agent, or directly if a UDP
hole punch succeeds; and device TCP ports are opened as PTCP "realms" for RTSP.

The protocol was reconstructed by reverse engineering gCMOB 3.4.1 (a rebranded Dahua
gDMSS) with [REA](https://github.com/morluto/rea), jadx and Ghidra, cross-checked
against the open-source clients listed below; `re/NOTES.md` has the evidence trail.
It builds on the MIT-licensed work of
[blackjid/dahua-p2p](https://github.com/blackjid/dahua-p2p),
[ludufre/dahua-p2p](https://github.com/ludufre/dahua-p2p),
[khoanguyen-3fc/dh-p2p](https://github.com/khoanguyen-3fc/dh-p2p) and
[undervolter/dh-fwd](https://github.com/undervolter/dh-fwd).

## Status

Verified on a CP Plus NVR (firmware 6.7.30) added by InstaOn serial number, streaming
H.265 through the relay. On connect, CamMob asks the recorder which channels have a
camera and uses the recorder's channel names. Devices registered with Dahua's own
Easy4ip cloud are supported by the same code path. Not yet implemented: playback, PTZ,
audio, two-way talk and alarms.

## Disclaimer

CamMob is an independent project, not affiliated with or endorsed by CP Plus, Aditya
Infotech or Zhejiang Dahua Technology. Use it only with recorders you own or are
authorised to access. MIT License.
