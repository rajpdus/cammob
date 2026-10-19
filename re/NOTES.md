# Reverse-engineering notes: gCMOB 3.4.1 (CP Plus) → CamMob

Produced with REA 6.5.0 (`inspect-android-package`, `analyze` on the native libs with
Ghidra 11), jadx 1.5.6 for the Java layer, and `strings` for a first pass. Raw outputs are
in `re/snapshots/` (gitignored), decompiled Java in `re/jadx/`, reference implementations in
`re/reference/`.

## What gCMOB is

* Package `com.mm.android.direct.g_CMOB_XU` (APKMirror bundle, base + 33 splits, 138 MB).
  `com.mm.android` is Dahua's namespace: gCMOB is a rebranded Dahua gDMSS/DMSS. The build path
  embedded in `libLoginComponent.so` says it outright:
  `PCSoft_DH3.RDA000193_DMSS_LCOpenSDK_Android_windows/.../CommonSDK-CMOB__2a5e44/`.
* Native libraries (arm64): `libnetsdk.so` (Dahua NetSDK, 1745 exported `CLIENT_*` functions,
  DHAV/DHIP markers, 131 JSON-RPC method names such as `configManager.getConfig`),
  `libLoginComponent.so` (device login + **Easy4IP P2P client**), `libEasy4IpComponent.so`
  (Easy4ip cloud REST: `/device/%s/…?client-id=%s`), `libNameSolution.so` (name/port resolution,
  WSSE header builder), `libLCBusiness.so` (LeChange/Imou cloud), `libgojni.so` (gomobile glue).
* Cloud hosts referenced by the app: `www.easy4ipcloud.com` (P2P server, `res/raw/config.xml`
  `<p2pServer>`), `www.dahuap2pcloud.com` (used only to test "is this a Dahua device"),
  `app.easy4ipcloud.com:443`, `mobile.easy4ipcloud.com`, `webview.dolynksecurity.com`.

## How gCMOB reaches a DVR by serial number

`libLoginComponent.so` contains the whole DH-HTTP-over-UDP handshake:

```
/probe/p2psrv   /online/p2psrv/   /online/relay   /online/stun   /probe/device/
/info/device/   /relay/agent      /relay/begin    /relay/bind/   /relay/start/
/relay/unbind/  p2p-channel       IpEncrptV2      DHGET          DHP2P
X-WSSE: UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"
```

plus the state machine strings (`tcp link ConnectStart`, `GetAgentSuccess`, `AgentBindStart`,
`AgentBindSuccess`, `WaitBindTimeout`, `CalcDevPwdFail`, `relay channel AgentFail`,
`relay channel IceWaitConfig`, `CPtcpChannel::onConnect`, `MODE_P2P`, `MODE_MTS`) and
`Dahua::Tou::DHP2P_SALT`. This is the same protocol that the open-source clients under
`re/reference/` reverse engineered from DMSS/SmartPSS captures, so CamMob ports those
(MIT licensed) rather than re-deriving packet formats from Ghidra output:

1. `DHGET /probe/p2psrv` and `/online/p2psrv/{SN}` on `www.easy4ipcloud.com:8800` → the P2P
   server holding the device; `/online/relay` → relay server.
2. `/probe/device/{SN}`, `/info/device/{SN}` on the P2P server → AES-OFB encrypted JSON with
   `randsalt`, `rtspport`, `privport` (37777), `httpport`.
3. `DHPOST /device/{SN}/p2p-channel` with our identify + local address (AES-OFB under
   PBKDF2(key, nonce) and an HMAC-SHA256 `DevAuth` when the device has a `randsalt`;
   key = MD5("user:Login to {randsalt}:pass") uppercase).
4. `/relay/agent` → agent + token; `/relay/start/{token}` on the agent;
   `DHPOST /device/{SN}/relay-channel` tells the device to join the agent.
5. PTCP ("phony TCP") over UDP: 24-byte header `PTCP|sent|recv|pid|lmid|rmid`, bodies
   SYNC 0x00, DATA 0x10, BIND 0x11, STATUS 0x12 (CONN/DISC), HEARTBEAT 0x13, handshake
   commands 0x17–0x1B (direct mode only). Device TCP ports are "realms" bound with BIND.
6. Over a realm to the RTSP port: ordinary RTSP with interleaved RTP, Digest auth,
   `rtsp://…/cam/realmonitor?channel=N&subtype=0|1`.

Relay mode is what works behind carrier-grade NAT (typical for Indian mobile/fibre ISPs);
direct mode (inverted-STUN hole punch, `0xfffeffe7` / `0xfefefff3` magics) is also implemented.

## Cloud credentials

The WSSE username/key for the Easy4ip servers are app-wide constants, not per user. gCMOB's
own pair (`P2P_AK_OVERSEA` / `P2P_SK_OVERSEA`) is read from `res/raw/test_encrypt`, an
AES-CBC blob decoded by `com.mm.logic.utility.KeyDecryptHelper` with a key derived from the
package name, and fed to `NameSolution.AddP2PInfo(server, SK, URL, port)` /
`setEasy4ipCloud(server)` in `LoginModule`. CamMob uses the pair the reference clients
recovered from SmartPSS Lite (`CloudCredentials.easy4ip`); it is accepted by the same servers.
The `d1cb775d…` constant in `libLoginComponent.so` sits next to `Reporter.cpp` and is a
telemetry id, not the P2P key.

## Why RTSP for video rather than NetSDK's 37777 stream

gCMOB pulls live video through NetSDK (`CLIENT_RealPlayEx`, DHAV frames over the private
port). The private protocol is a second, undocumented binary layer (login handshake,
sub-connection for realplay, DHAV framing) on top of the same tunnel. The DVR also serves
RTSP on the tunnel's `rtspport`, which carries the identical H.264/H.265 streams, so CamMob
tunnels RTSP first. The P2P transport, which is the part that makes "add by serial number"
work, is exactly what gCMOB does. A DHIP/JSON-RPC client over 37777 (for channel names and
device info) is the natural next step; the method names are all in `libnetsdk.so`.

## InstaOn: what actually connects a CP Plus recorder

A CP Plus DVR added "by serial number" in gCMOB uses **Add Mode: InstaOn**, not Dahua's
public Easy4ip. Two services are involved:

1. `www.instaon.com` SOAP registry (`/webservice/GetDeviceInterface`, method
   `getDeviceByDevSequence`, namespace `http://webservice.ddns.dahua.com/`): returns the
   recorder's registration JSON (public IP, private/HTTP/RTSP ports, MAC, `visit:"p2p"`,
   `p2ptype:"dhp2p"`, firmware). Built into `libNameSolution.so` as the envelope templates.
2. `instaonserver.com:8800`, CP Plus's own Easy4ip-protocol P2P cloud. Its address and the
   app's WSSE pair come from `res/raw/test_encrypt.test`, AES-256-CBC with a key derived
   by PBKDF2-SHA1 from `BuildConfig.RANDOM_STR` and an IV from the package name + version
   (`KeyDecryptHelper`). Keys: `P2P_SERVER_OVERSEAS`, `P2P_PORT`, `P2P_AK_OVERSEA`,
   `P2P_SK_OVERSEA`; the Java layer feeds them to
   `LoginSAASModule.initAfterP2P(server, port, AK, SK, …)`.

Against firmware 6.7.30 the legacy (SmartPSS-style) request shape is refused with
`403 DevPwd_InvalidSalt`; the DMSS-era dialect that gCMOB speaks is accepted:
`X-Version: 6.7.15`, `X-Sversion: 1.1.0`, `x-pcs-request-id`, `X-ToUType: Client/Dmss_Android`,
random signed CSeq, local-time `Created` with numeric offset, and a channel body of
`Identify / IpEncrptV2 / NatValueT / version / sVersion / LocalAddr / Pid / ClientId`.
`relay-channel` needs a fresh nonce (reusing the channel nonce gives `DevPwd_InvalidNonce`).
The DevAuth math itself was confirmed from Ghidra:
`Dahua::Tou::CDevicePasswordAuth::calcDevPwdAuth` = `getDevicePwdMd5(user, pass, salt)`
then HMAC-SHA256 over nonce ‖ date ‖ payload, base64. After the device joins the agent the
app sends SYNC only (no 0x17/0x19 token auth) and tries a STUN punch to the device's
public address; behind CGNAT that fails and the relay carries the stream.

## Channel list and names: the recorder's CGI over the tunnel

The device's HTTP port (from `/info/device`, normally 80) is reachable as another PTCP
realm. Its Dahua-style CGI answers with Digest auth (`qop=auth`) and `Connection: close`,
so each request is one realm. `LogicDeviceManager.cgi?action=getCameraAll` lists every
slot with `UniqueChannel`, `Enable` and `Type` (`Remote`, `Local`, or `Compose` for the
multi-view pseudo channel); `configManager.cgi?action=getConfig&name=ChannelTitle` gives
the names. CamMob shows the enabled, non-Compose slots. An 8-slot NVR with 6 cameras
therefore shows 6 tiles, not the 4 the gCMOB device card claimed.

Under load the device's retransmissions showed that PTCP sequence numbers count bytes:
a retransmitted datagram may bundle several bodies or start inside one. The receiver
now reassembles a byte stream and frames bodies by their 12-byte length header (SYNC
and the 0x17–0x1B handshake commands have no length and stay one per datagram).
Before that fix, long CGI replies were silently truncated at datagram boundaries.

Some cameras never answer an RTSP `DESCRIBE` for `subtype=1`; the main stream works.
CamMob retries a failed channel and falls back to the main stream.

## Not done / caveats

* Validated live against a CP Plus NVR (fw 6.7.30, InstaOn): relay tunnel, RTSP sub stream,
  H.265 frames decoded. The direct punch did not succeed from a CGNAT-ed link, as expected.
* The device's encrypted `LocalAddr` in the channel reply does not decrypt with the
  address key/IV used for our own address (another IV, `PROXY_AES_DEVAUTH_IV`, exists in
  the library); it is ignored unless it decrypts to a clean `ip:port`.
* Devices with firmware after 2024-07 require the device user/password for `p2p-channel`
  (HTTP 403 otherwise); CamMob always sends them when a `randsalt` is present.
* One relay session per device at a time; the device keeps a closed one for ~15–20 s.
  `Tunnel.open` retries on "device busy" for 35 s.
