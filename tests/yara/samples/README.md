# YARA test samples

These artifacts are **synthetic and inert**. They exist to exercise the YARA
rules with the structural features those rules target — a project marker next to
a structurally coherent embedded PE, a firmware marker next to an embedded PE, a
dropper-shaped PowerShell script, and an OOXML document with a macro project —
not to be executable malware.

## Structural PE checks

The firmware, Siemens project and macro-document rules no longer match a file
that merely contains `MZ` and `PE\0\0` somewhere. A positive fixture must carry a
PE with a coherent header chain:

- `MZ` (`uint16(offset) == 0x5A4D`) at a bounded offset;
- `e_lfanew` at `offset + 0x3C` in the small, bounded range `0x40..0x1000`;
- `offset + e_lfanew + 4` inside the file; and
- `PE\0\0` (`0x00004550`) at `offset + e_lfanew`.

`benign/*_bare_mz.bin` and `benign/ews_macro_bare_mz.docm` deliberately contain
the marker, a bare `MZ` and an unrelated `PE\0\0` string. They matched the old
substring-only rules and must not match the structural rules.

YARA-X exposes a `pe` module, but `pe.is_pe` only parses a PE whose `MZ` header
is at file offset 0. These artifacts embed the PE after a marker, so the rules
use bounded `uint16`/`uint32` arithmetic over the `MZ` occurrences instead. The
macro-document rule uses the available YARA-X `zip` module (`zip.is_zip`) so a
flat file with the OOXML part names concatenated into it is not accepted as a
container.

## Fixtures

- `malicious/` contains the marker patterns only. The "PE" is a coherent but
  inert header chain with a synthetic payload string; nothing in it runs. The
  `.docm` files are real ZIP/OOXML containers (stored uncompressed) with
  `[Content_Types].xml`, `word/document.xml` and `word/vbaProject.bin`.
- `benign/` contains the same kind of artifact without the full positive shape,
  so each rule has an adversarial near-miss, not just an unrelated file:
  - a macro-enabled document with no embedded binary;
  - a macro-enabled document with bare `MZ`/`PE` bytes but no valid PE header;
  - a document with a valid embedded PE but no macro project;
  - firmware and project files with bare `MZ`/`PE` bytes but no valid PE;
  - a routine PowerShell script, a `Start-Process iexplore.exe` browser
    launcher (the `IEX` substring), an admin script using `-Encoding UTF8` (the
    `-enc` substring), and a download-only script with a single loader
    behaviour.
- `payloads/` is a synthetic protocol payload blob used to prove the same rules
  can scan a payload rather than a file.

The PowerShell rule requires a real `Invoke-Expression`/`IEX` invocation plus at
least two loader behaviours: an encoded command with a base64-looking blob, a
remote download, or an in-memory assembly load. The positive fixtures exercise
the encoded+download and download+in-memory paths. A bare `IEX` substring in
`iexplore.exe`, a bare `-enc` substring in `-Encoding`, and a download with no
execution therefore stay negative.

## Why no real malware

Committing live malware is unsafe, usually illegal, violates the hosting terms,
and is not what a detection-engineering portfolio should demonstrate. The rules
name real technique ids and real artifact structure; the fixtures are safe to
clone and run.

The engine is additionally proven against the **EICAR standard antivirus test
file**, assembled in memory by `tools/yara_check.py` and never written to disk.
That gives one recognised, genuinely malicious *signature* without shipping
malware.
