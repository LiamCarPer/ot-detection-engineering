rule OT_Macro_Document_With_Embedded_PE
{
  meta:
    author = "Liam Carvajal"
    description = "A macro-enabled Office document that carries an embedded Windows executable, the shape of a spearphishing attachment that drops a payload on an engineering workstation."
    date = "2026-11-04"
    attack_ics = "T0865"
    reference = "https://attack.mitre.org/techniques/T0865/"
    level = "high"
  strings:
    $office = "[Content_Types].xml" ascii wide
    $macro = "vbaProject.bin" ascii wide nocase
    $mz = { 4D 5A }
    $pe = "PE\x00\x00"
  condition:
    $office and $macro and $mz and $pe
}
