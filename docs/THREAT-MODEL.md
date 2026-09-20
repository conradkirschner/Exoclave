# Threat model

Read this before trusting any Exoclave output. It explains what the tool can
prove, what it can only suggest, and where it is blind.

## The rule everything follows

> A claim is only as strong as the adversary that could not have forged it.

Every piece of evidence Exoclave records carries a **trust basis**, and every
finding inherits the weakest basis among its evidence. The report then states,
per adversary tier, whether the run could speak to that tier at all. This is
enforced in `crates/ps-model/src/trust.rs`; there is no way to express "the
device is clean" in the domain model.

## Tiers

### 1. App level — *covered*

An ordinary installed application. No root. It abuses Accessibility Services
(the mechanism behind overlay attacks, keylogging and remote control),
notification listeners, device administrator registration, and the
"install unknown apps" permission.

Every commercial stalkerware product and every Android banking trojan
(Anatsa, Octo, Hook, Medusa, Cerberus, Crocodilus and relatives) lives here.

- **Why the device's own answers are good enough:** an app cannot rewrite
  `dumpsys` or filter `pm list packages`. It can hide its launcher icon, which
  defeats the phone's UI — and not ADB.
- **Remediation is reliable:** these live entirely in `/data`. A factory reset
  removes them. Verified Boot means they never touched `/system`.

### 2. Privileged persistent — *planned*

A system app, a Magisk-style module, or an unlocked bootloader. Survives a
factory reset. Defeats the OS's own reporting.

- **Detectable, but not from `getprop`.** Root can rewrite
  `ro.boot.verifiedbootstate`. What it cannot forge is a **hardware key
  attestation** certificate: a chain signed inside the TEE or StrongBox,
  carrying `RootOfTrust` (verified boot state, bootloader lock, patch level)
  and verifiable against the vendor root **on the host**.
- Non-software corroboration a kernel implant cannot touch: the bootloader's
  own warning screen at boot, and `fastboot getvar unlocked`.
- **Asymmetry worth knowing:** Exoclave reports a *non-green* boot state from
  the device but draws no conclusion from a green one. No implant benefits from
  understating device integrity, so the adverse answer is credible while the
  favourable one is not.

### 3. Runtime kernel — *planned, and the hard one*

Root obtained through a kernel or OEM-driver exploit **after** boot. Nothing on
disk changes.

This is the tier that invalidates most tooling, including Exoclave's current
ADB path:

- Verified Boot still reports green, and **hardware attestation still passes** —
  both attest the *boot chain*, not the *running kernel*. Accurate and
  irrelevant at the same time.
- OEM driver code is not upstream Linux, so the Android security patch level
  does not track it.
- On-device root detection is useless: the detector runs at lower privilege
  than the implant.
- Everything in an androidqf/ADB acquisition is forgeable.

What can still reach it:

1. **Out-of-band observation.** A kernel implant controls everything the phone
   reports. It does not control a router it does not own. Packets crossing our
   own access point are ground truth — hence the isolated-hotspot component on
   the roadmap.
2. **Cross-source contradiction.** A rootkit filtering one enumeration path
   rarely filters all of them consistently. Compare `pm list packages` against
   `dumpsys package`, the bugreport and `/data/app`; compare the device's app
   list against Google Play's server-side install history; compare
   `getprop ro.build.version.security_patch` against the *attested* patch
   level; and above all compare `dumpsys netstats` against what our access
   point actually logged. A phone reporting 2 MB while the router saw 40 MB
   uploaded is not a heuristic — it is a caught lie.
3. **Reboot discrimination.** Non-persistent root dies on reboot, by design.
   Baseline, reboot, baseline again.

**Remediation beats detection here.** A tier-3 implant has no disk persistence,
so on a locked bootloader with verified boot green, a factory reset plus an
update to a patched build removes it with near-certainty — without ever having
detected it.

### 4. Boot chain — *out of scope*

Bootloader, TEE or signed firmware compromise. Defeats attestation itself. No
host-side tool can rule this in or out. Below-OS acquisition (MediaTek BROM,
Qualcomm EDL, JTAG, chip-off) is laboratory work, and note that unlocking a
bootloader to obtain a dump wipes userdata on modern Android — destroying the
evidence you wanted.

## State-grade spyware

Exoclave cannot reliably detect Pegasus-class implants, and neither can anything
else you can run at home. They are frequently non-persistent, leave minimal
artifacts, and Android forensics is substantially weaker than iOS. Amnesty's
Security Lab and Citizen Lab, with full device access and non-public campaign
intelligence, catch a subset.

What Exoclave does at that tier is narrower and honest: collect the right
artifacts to a forensic standard so a real lab could analyse them later, match
published indicator sets, hunt contradictions rather than signatures, and
report calibrated coverage.

## Consequences for the user

- A quiet scan means *"no indicators found, at the tiers this run covered, with
  these feeds, on this date."* Nothing more.
- If the device no longer receives security updates, an unpatched OEM driver is
  a permanent re-entry path. Detection and cleaning are both temporary; replace
  the device.
- Detection failure is silent. When the stakes are real, the reliable move is a
  factory reset without restoring a backup — or a full stock reflash with the
  bootloader re-locked — plus rotating credentials from a different machine.
- Account compromise survives every one of the above. A phone reset does nothing
  about a registered TAN device, an added recovery address, a mail forwarding
  rule, or a live session.
