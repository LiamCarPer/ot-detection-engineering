rule OT_Siemens_Project_File_With_Embedded_PE
{
  meta:
    author = "Liam Carvajal"
    description = "A Siemens project file that carries an embedded Windows executable, consistent with a project-file infection. The embedded image must have a coherent MZ/e_lfanew/PE header chain, not just the marker bytes."
    date = "2026-11-04"
    attack_ics = "T0873.001"
    reference = "https://attack.mitre.org/techniques/T0873/001/"
    level = "high"
  strings:
    $project = "SIMATIC" ascii wide nocase
    $mz = { 4D 5A }
  condition:
    $project and
    filesize >= 0x44 and
    // YARA-X's pe module only parses a PE at offset 0 (pe.is_pe); project
    // files embed the PE after a marker, so validate the header chain arithmetically.
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
