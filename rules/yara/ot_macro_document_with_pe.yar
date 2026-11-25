import "zip"

rule OT_Macro_Document_With_Embedded_PE
{
  meta:
    author = "Liam Carvajal"
    description = "A macro-enabled Office document that carries an embedded Windows executable, the shape of a spearphishing attachment that drops a payload on an engineering workstation. The document must be an OOXML/ZIP container with a macro project, and the PE must have a coherent MZ/e_lfanew/PE header chain, not just the marker bytes."
    date = "2026-11-04"
    attack_ics = "T0865"
    reference = "https://attack.mitre.org/techniques/T0865/"
    level = "high"
  strings:
    $office = "[Content_Types].xml" ascii wide
    $macro = "vbaProject.bin" ascii wide nocase
    $mz = { 4D 5A }
  condition:
    // The zip module proves this is a real OOXML/ZIP container, not a flat
    // file with the part names concatenated into it.
    zip.is_zip and
    $office and $macro and
    filesize >= 0x44 and
    // YARA-X's pe module only parses a PE at offset 0 (pe.is_pe); the payload
    // here is embedded inside the document, so validate the header chain with
    // bounded uint16/uint32 arithmetic instead.
    for any i in (1..#mz) : (
      @mz[i] < 0x1000000 and
      @mz[i] + 0x40 <= filesize and
      uint16(@mz[i]) == 0x5A4D and
      uint32(@mz[i] + 0x3C) >= 0x40 and
      uint32(@mz[i] + 0x3C) <= 0x1000 and
      @mz[i] + uint32(@mz[i] + 0x3C) + 4 <= filesize and
      uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
    )
}
