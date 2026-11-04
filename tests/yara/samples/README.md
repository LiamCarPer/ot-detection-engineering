# YARA test samples

These artifacts are **synthetic and inert**. They exist to exercise the YARA
rules with the structural features those rules target — a project marker next to
an embedded PE, a firmware marker next to an embedded PE, a dropper-shaped
PowerShell script — not to be executable malware.

- `malicious/` contains the marker patterns only. The "PE" is an `MZ` header, a
  `PE\0\0` signature and an inert string; nothing in it runs.
- `benign/` contains the same kind of artifact without the marker pattern, so
  each rule has a near-miss negative, not just an unrelated file.
- `payloads/` is a synthetic protocol payload blob used to prove the same rules
  can scan a payload rather than a file.

## Why no real malware

Committing live malware is unsafe, usually illegal, violates the hosting terms,
and is not what a detection-engineering portfolio should demonstrate. The rules
name real technique ids and real artifact structure; the fixtures are safe to
clone and run.

The engine is additionally proven against the **EICAR standard antivirus test
file**, assembled in memory by `tools/yara_check.py` and never written to disk.
That gives one recognised, genuinely malicious *signature* without shipping
malware.
