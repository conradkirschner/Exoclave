# phone-scanner — Windows Wi-Fi hotspot as an off-device phone scanner

**Goal:** turn this Windows 11 laptop into a disposable, isolated Wi-Fi access point. A
suspect phone joins it, all its traffic is NATed through the PC, and the PC logs + scores
DNS queries, TLS/QUIC SNI, and IP flows against threat-intel indicators. Nothing is
installed on the phone.

Status: **planning**. Nothing implemented yet.

---

## 1. Verdict on feasibility

**Feasible on this exact machine**, with three traps that must be designed around
(sections 3-5). It is *not* a virus scanner: it sees network behaviour, never files.
A clean result means "no known-bad traffic during the observation window", not "clean phone".

### Checked on this hardware (2026-09-19)

| Check | Result | Consequence |
|---|---|---|
| Wi-Fi adapter | Intel Wi-Fi 6 AX201, driver 23.170.0.1 | ok |
| `netsh wlan show drivers` -> hosted network | **No** | legacy `netsh wlan start hostednetwork` is dead, must use Win11 Mobile Hotspot |
| Wi-Fi Direct GO | **Supported**, 1 GO port, max 8 clients | Mobile Hotspot (WinRT `NetworkOperatorTetheringManager`) will work |
| Simultaneous channels | 0 | AP is forced onto the upstream Wi-Fi channel when sharing Wi-Fi to Wi-Fi |
| Ethernet (I219-LM) | present but **disconnected** | **plug it in** so the radio is free for the AP and isolation is cleaner |
| ICS services | `SharedAccess` running, `icssvc` manual | ready |
| Npcap / tshark | **not installed** | prerequisite |
| Python | 3.14.6 | ok |
| Hyper-V + WSL2 | present | useful for the fallback in section 7 |

**Isolation:** the hotspot puts the phone on `192.168.137.0/24` behind NAT. It cannot reach
`192.168.1.0/24` (your LAN) at all unless we route it. That is the real security win of
this design and it holds even when sharing the Wi-Fi uplink.

---

## 2. What you can actually observe

| Signal | Visible? | Notes |
|---|---|---|
| Plain DNS (UDP/TCP 53) | yes | only if we own the resolver, see section 3 |
| DNS-over-TLS (853) | no | defeatable: do not answer 853 on our own resolver IP, Android "Automatic" then falls back to plain |
| DNS-over-HTTPS | no | partially defeatable via canary domains (section 4), otherwise only detectable, not readable |
| TLS SNI (ClientHello) | yes | unless Encrypted Client Hello, which is growing. Treat as a known blind spot |
| QUIC SNI | yes | tshark decrypts the QUIC Initial packet |
| Destination IP / ASN / port | yes | always available, the reliable fallback when SNI is hidden |
| Beaconing / periodicity / volume | yes | strong signal for stalkerware and C2 |
| HTTP payload, headers, User-Agent | no | only with MITM (section 6, optional and limited) |

---

## 3. Trap 1 - the DNS path on Windows ICS

Windows ICS runs its **own DNS proxy** on `192.168.137.1:53` and forwards phone queries
onward as host traffic. Two problems:

1. We never see the queries at application level.
2. Sniffing them is unreliable: [npcap#713](https://github.com/nmap/npcap/issues/713) -
   on Windows 11, unicast UDP between a hotspot client and the host is **not captured** by
   Npcap (Microsoft Network Monitor sees it, Windows 10 is fine). Forwarded internet-bound
   traffic *is* captured. DNS to the ICS proxy is exactly the broken case.

**Solution: do not sniff DNS, be the DNS server.**

- Set `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\EnableDnsProxy = 0`
- ICS's DHCP allocator still hands out `192.168.137.1` as the client DNS server
- Bind our own resolver on `192.168.137.1:53`

Result: a structured query log (client MAC/IP, qname, qtype, timestamp, answer) plus the
ability to sinkhole. **This assumption must be verified in the Phase-0 spike.** If ICS
refuses, fall back to binding our resolver on a loopback alias and pointing the host's
upstream DNS at it (dirtier: the host's own queries mix in).

---

## 4. Trap 2 - encrypted-DNS bypass

Modern phones route around plain DNS. Countermeasures, in order of leverage:

| Bypass | Countermeasure |
|---|---|
| Android Private DNS = *Automatic* (opportunistic DoT) | our resolver simply does not listen on 853, the probe fails, phone falls back to plain DNS. Free. |
| Android Private DNS = *hostname* | fails closed, phone has no DNS at all. **Must be switched off manually**, pre-flight checklist item. |
| Firefox DoH | answer `use-application-dns.net` with **NXDOMAIN**, Firefox disables DoH itself |
| Chrome auto-DoH | only upgrades when the configured resolver is a known DoH provider. `192.168.137.1` is not, so no upgrade. Free. |
| iCloud Private Relay | NXDOMAIN for `mask.icloud.com` and `mask-h2.icloud.com`, Apple's documented network-operator method |
| App with hardcoded DoH/DoT IPs (real spyware does this) | **cannot block cheaply.** Windows Firewall does not filter *forwarded* traffic, the WFP IPFORWARD layer is not exposed to it. Detect instead: flag any hotspot -> known-DoH-IP:443/853 flow as "DNS visibility incomplete". Stretch goal: WinDivert `NETWORK_FORWARD` layer (LGPL-3.0) to drop it. |

Also in the pre-flight checklist: disable Wi-Fi MAC randomisation for this SSID (or just
pin to the single client), disable any VPN on the phone, and keep the phone on the hotspot
for a meaningful window (30-60 min minimum, ideally overnight).

---

## 5. Trap 3 - interpretation, not capture

A normal phone emits thousands of DNS queries per hour, nearly all to CDNs. Raw logs are
useless without scoring. Worse: competent spyware rides Firebase/FCM, AWS and Google
infrastructure and looks exactly like a normal app.

So the detection layer is the product, not the hotspot:

- **IOC matching** - domains, IPs, `IP:port` against maintained feeds
- **Stalkerware-specific indicators** - the Echap set, used by both TinyCheck and MVT
- **Heuristics** - newly-registered domains (RDAP), DGA/entropy scoring, DNS-tunnelling
  patterns (long high-entropy labels, TXT/NULL floods), periodic beaconing, traffic to
  hosting ASNs with no matching installed app, exfil-shaped upload/download ratios,
  connections during device-idle windows
- **Baselining** - record a known-good phone once, diff against it

And say it plainly in the report: good sensitivity for *known* commercial stalkerware, poor
sensitivity for targeted or zero-day implants. Pair with on-device forensics (MVT) for
anything serious.

---

## 6. Architecture

```
        [ suspect phone ]
               | Wi-Fi  (SSID: scanner-xxxx, WPA2)
   +-----------v-----------------------------------------+
   | Windows 11 laptop                                   |
   |                                                     |
   |  Mobile Hotspot (WinRT) -- 192.168.137.1/24 -- NAT -+--> Ethernet (uplink)
   |        |                          |                 |
   |        |                          +- Npcap sensor --+   flows, TLS/QUIC SNI, IP/ASN
   |        |                                            |
   |        +- our DNS resolver :53 ---------------------+   query log, sinkhole, canaries
   |                                                     |
   |   detection engine  ->  SQLite session store  ->  local web report (FastAPI)
   +-----------------------------------------------------+
```

### Phases

**Phase 0 - spike (half a day). Do this before writing any product code.**
Answer four questions with throwaway scripts:

1. Does Mobile Hotspot start/stop reliably from script (WinRT `NetworkOperatorTetheringManager` via PowerShell or `pythonnet`)?
2. With `EnableDnsProxy=0`, do clients still get `192.168.137.1` as their DNS server, and can we bind `:53` there?
3. Does Npcap on the hotspot adapter (`LAN-Verbindung* N`) capture forwarded phone traffic, including TLS ClientHello and QUIC Initial?
4. Does a phone actually get working internet through it?

If 2 or 3 fails, switch to section 7 before investing further.

**Phase 1 - AP control.** Start/stop the hotspot, generate a random SSID and WPA2
passphrase per session, show a QR code for joining, wait for and identify the client, tear
everything down (including the registry change) on exit.

**Phase 2 - DNS resolver.** `dnslib`-based forwarder, upstream over DoH to a resolver of
your choice so *your* DNS stays private. Log every query to SQLite. Implement the canary
answers from section 4. Optional sinkhole mode.

**Phase 3 - packet sensor.** `tshark -i <hotspot> -T ek` with fields for `dns`,
`tls.handshake.extensions_server_name`, `quic`, `ip`, `tcp`/`udp`, piped to JSON lines and
into SQLite. tshark is far more robust than hand-rolled Scapy parsing for QUIC and TLS.
Keep the raw pcap as evidence.

**Phase 4 - detection.** Feed loader (cached, offline-capable), matcher, heuristics, and a
per-finding severity plus a plain-language explanation. See section 8 for what to reuse
instead of writing.

**Phase 5 - report.** Local web UI: session timeline, top destinations, findings ranked by
severity with their evidence (query, timestamp, matched feed), export to HTML/JSON.

**Phase 6 - optional MITM.** mitmproxy for apps without certificate pinning. iOS: install
and trust a profile. Android 7+: user CAs are not trusted by apps, so this is largely a
dead end without root. Low value-to-effort, do it last if at all.

**Phase 7 - cross-check.** Wire up MVT for an on-device pass (iOS backup / Android ADB).
Far more conclusive than network analysis. Different licence, so keep it as an external
tool the report links to, not a vendored dependency.

---

## 7. Escape hatches if Phase 0 fails

- **B - USB Wi-Fi dongle + WSL2.** `usbipd-win` passthrough, `hostapd` + `dnsmasq` in
  Linux. Full control, dnsmasq logs every query, Suricata and Zeek work natively. Cost: a
  custom WSL2 kernel with `mac80211` and the dongle's driver.
- **C - OpenWrt travel router as the AP**, PC runs the analysis on a mirrored or streamed
  capture. Most robust, least "Windows tool".
- **D - no hotspot at all.** Point the phone's Wi-Fi DNS manually at the PC's LAN IP and
  run a DNS server there. Ten minutes of work, gives you the DNS log, loses the isolation
  and the flow/SNI data. A good smoke test for whether the detection layer is worth
  building at all.

---

## 8. Prior art

Direct answer to "is someone already doing this": **yes, several projects. All of them are
Linux / Raspberry Pi, and none of them is MIT.**

### Does the whole job (AP + capture + IOC), Linux only

| Project | Licence | State | Notes |
|---|---|---|---|
| [TinyCheck](https://github.com/PowerPress/TinyCheck) (Kaspersky) | **Apache-2.0** | original `KasperskyLab/TinyCheck` now returns **404**, only forks and an [Internet Archive copy](https://archive.org/details/github.com-KasperskyLab-TinyCheck_-_2020-12-04_16-29-48) remain | the reference implementation of exactly this idea. Debian plus two Wi-Fi interfaces, built with a women's shelter to check for stalkerware |
| [SpyGuard](https://github.com/SpyGuard/SpyGuard) | **Apache-2.0** | fork of TinyCheck by the original author, itself now stale | enhanced flow monitoring |
| [SpyCheck](https://codeberg.org/spycheck/spycheck) | licence not stated in the README, **must be confirmed** | **active**, commits into 2026, German Prototype Fund / BMBF funded | explicit successor to TinyCheck and SpyGuard. Written in **Go**, so a Windows port is plausible. Linux + NetworkManager + libpcap today, no TLS decryption by design |
| [spytrap-wifi](https://github.com/spytrap-org/spytrap-wifi) | **GPL-3.0** | stale since 2022, 15 stars | Rust, hotspot plus DPI |
| [PiRogue Tool Suite](https://pts-project.org/) | **GPL-3.0** | active | Raspberry Pi router, NFStream DPI plus Suricata. The most complete forensics platform of the group |

### MIT building blocks that already run on Windows

| Project | Licence | Why it matters here |
|---|---|---|
| **[Maltrail](https://github.com/stamparm/maltrail)** | **MIT** | The big one. Active (pushed 2026-09-17), 8.6k stars. Matches domains, URLs, IPs, `IP:port` and User-Agents against 3000+ bundled trail files and 42 public feeds. Ships a **prebuilt Windows x86_64 sensor** (Rust, libpcap, needs Npcap) plus a browser reporting UI with live updates, retro-hunting and export. That is most of Phase 4 and Phase 5, MIT, already on Windows. |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | MIT | optional Phase 6 |
| [pyshark](https://github.com/KimiNewt/pyshark) | MIT | tshark wrapper for Phase 3. tshark itself is GPL-2.0 but is invoked as a subprocess |

### Complementary / reference

- **[MVT](https://github.com/mvt-project/mvt)** - licence reports as `NOASSERTION` (custom
  MVT licence, not OSI-MIT). On-device forensics for iOS and Android. Keep it external.
- **[stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)** (Echap)
  - **no licence file at all**. The canonical stalkerware IOC set used by TinyCheck and
  MVT. Do not vendor it: fetch at runtime and attribute, or ask the maintainers.
- DNS servers with query logging that run on Windows: AdGuard Home (GPL-3.0), Technitium
  (GPL-3.0), Blocky (Apache-2.0), CoreDNS (Apache-2.0). Pi-hole is EUPL and Linux only.

### Conclusion

The gap is real and narrow: **Windows AP orchestration, DNS control, and a phone-oriented
report.** Everything downstream of the capture can be Maltrail (MIT). If this project is to
be MIT-licensed, do not copy TinyCheck or SpyGuard code - Apache-2.0 is fine to depend on
but cannot be relicensed as MIT. Take the idea, write the Windows half fresh, shell out to
Maltrail.

Worth doing first: open an issue on SpyCheck asking about its licence and Windows plans. If
they intend a Windows port, contributing a Windows AP backend to an active Go codebase
beats maintaining a parallel Python tool.

---

## 9. Legal note

Only scan a device you own or have explicit consent to scan. If this is a suspected
stalkerware case involving another person, the evidence handling and the safety plan matter
more than the tooling - see the Coalition Against Stalkerware.
