rule OT_S7_Firmware_With_Embedded_PE
{
  meta:
    author = "Liam Carvajal"
    description = "An S7 controller firmware image that contains an embedded Windows executable, a marker of a tampered firmware package."
    date = "2026-11-04"
    attack_ics = "T1693.001"
    reference = "https://attack.mitre.org/techniques/T1693/001/"
    level = "high"
  strings:
    $firmware = "S7-1500" ascii wide nocase
    $mz = { 4D 5A }
    $pe = "PE\x00\x00"
  condition:
    $firmware and $mz and $pe
}
