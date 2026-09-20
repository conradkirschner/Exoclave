<h1 align="center">Exoclave</h1>

<p align="center">
  <em>Examine an Android phone from a computer it cannot tamper with.</em>
</p>

<p align="center">
  <a href="#status"><img alt="status" src="https://img.shields.io/badge/status-early%20development-orange"></a>
  <a href="LICENSE"><img alt="licence" src="https://img.shields.io/badge/licence-MIT-blue"></a>
  <img alt="rust" src="https://img.shields.io/badge/rust-2024%20edition-black">
  <img alt="build" src="https://img.shields.io/badge/build-docker%20only-informational">
</p>

---

Exoclave inspects a possibly-compromised Android device and tells you what it
found, what it checked, and — in the same breath — **what it could not see.**

It never says the word *clean*.

## Why another one

Mobile forensic tools collect what the device says about itself and match it
against indicator lists. That is exactly right for a banking trojan or
commercial stalkerware, which are ordinary apps and cannot rewrite `dumpsys`
output. It is worth nothing against an implant that obtained kernel privileges
through an unpatched driver — that implant edits the answers.

Most tools present both cases with the same confident green tick.

Exoclave refuses to. Every piece of evidence carries a **trust basis** — who
could have forged it — and the report states, per adversary tier, whether the
run could speak to that tier at all.

```
  Reported by the device itself        →  credible against an app
  Signed inside the secure element     →  credible against a kernel implant,
                                          but only about the boot chain
  Observed on our own access point     →  the device cannot edit this
  Two sources disagreeing              →  the contradiction is the evidence
```

That is a type in the codebase, not a disclaimer in a footer:

```rust
assert!( TrustBasis::SelfReported.is_credible_against(ThreatTier::AppLevel));
assert!(!TrustBasis::SelfReported.is_credible_against(ThreatTier::RuntimeKernel));
assert!( TrustBasis::OutOfBand   .is_credible_against(ThreatTier::RuntimeKernel));
```

## Threat tiers

| Tier | What it is | Can Exoclave see it? |
|---|---|---|
| **App level** | A malicious app abusing Accessibility, overlays, device admin. All commercial stalkerware; every banking trojan. | **Yes.** This is the tool's home ground. Removed by a factory reset. |
| **Privileged persistent** | System app, Magisk-style module, unlocked bootloader. Survives a reset. | **Planned** — needs hardware key attestation, verified on the host. |
| **Runtime kernel** | Root via an exploit *after* boot. Nothing on disk changes, so Verified Boot still reports green: attestation covers the boot chain, not the running kernel. Dies on reboot. | **Planned** — only out-of-band network observation and cross-source contradiction can reach it. |
| **Boot chain** | Bootloader, TEE or signed firmware. | **No.** No host-side tool can. Laboratory work. |

Read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) before trusting any output.

## What it does not do

Being explicit, because security tools routinely are not:

- **It cannot reliably detect state-grade spyware.** Pegasus-class implants are
  frequently non-persistent and leave minimal artifacts; Android forensics is
  far weaker than iOS. Amnesty's Security Lab and Citizen Lab, with full device
  access and non-public intelligence, catch a subset. Anything claiming
  otherwise is selling something.
- **It cannot read your Google backup.** Android backups have been
  end-to-end encrypted with the lock-screen secret since Android 9, sealed in
  Titan HSMs. Google cannot read them either. The restore-advice feature works
  from a Google Takeout export you produce yourself instead.
- **A quiet result is not a clean result.** See the coverage statement, every
  single time.

## Quick start

Docker is the only prerequisite. No Rust toolchain, no MSVC, no platform setup.

```bash
git clone https://github.com/conradkirschner/Exoclave.git
cd Exoclave
make check          # fmt + clippy + tests, in the build image
make build          # release image
```

Scanning a device. A Linux container cannot claim a USB device on Windows or
macOS, so Exoclave talks to an adb **server** on the host — no USB passthrough,
no extra privileges:

```bash
# on the host, once
adb -a -P 5037 nodaemon server

# then
make run ARGS="scan --feed /feeds/example.json --json /work/report.json"
```

Or natively, if you do have a Rust toolchain:

```bash
cargo run -p ps-cli -- scan --feed feeds/example.json
```

## Layout

```
crates/
  ps-model      domain model — threat tiers, trust provenance, findings, coverage
  ps-adb        typed ADB access; parsers separated from I/O and unit-tested
  ps-analyze    detection modules, indicator feeds, coverage statement
  ps-cli        terminal front end
docker/         the entire build chain
docs/           threat model and research notes
feeds/          indicator feed format, with an example
```

Detection runs against replayed fixtures, so the whole pipeline is exercised in
CI with no phone attached — see `ps_adb::fake::FakeShell`.

## Roadmap

- [x] Domain model with trust provenance and honest coverage
- [x] ADB acquisition and app-tier detection
- [x] Reproducible Docker build chain
- [ ] Web UI (axum + browser) with a guided cleanup wizard
- [ ] Hardware key attestation, verified host-side
- [ ] Google Takeout parsing → per-app *safe to restore?* verdicts
- [ ] Out-of-band capture: isolated Wi-Fi hotspot, own DNS resolver, TLS/QUIC SNI
- [ ] Cross-source contradiction engine — where a kernel implant actually gets caught
- [ ] Indicator feed fetchers (attribution-preserving)

## Licence and attribution

MIT — see [LICENSE](LICENSE).

Exoclave deliberately shares no code with existing projects in this space, whose
licences differ: TinyCheck and SpyGuard are Apache-2.0, PiRogue and spytrap are
GPL-3.0, and MVT and androidqf are under the custom MVT licence. Indicator feeds
carry their own terms — the widely used stalkerware set from Echap is CC-BY and
requires attribution, which is why every loaded feed's licence is recorded in
the report.

## Consent

Use this only on a device you own or have explicit permission to examine.
