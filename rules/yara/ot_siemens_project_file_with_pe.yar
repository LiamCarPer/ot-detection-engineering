rule OT_Siemens_Project_File_With_Embedded_PE
{
  meta:
    author = "Liam Carvajal"
    description = "A Siemens project file that carries an embedded Windows executable, consistent with a project-file infection."
    date = "2026-11-04"
    attack_ics = "T0873.001"
    reference = "https://attack.mitre.org/techniques/T0873/001/"
    level = "high"
  strings:
    $project = "SIMATIC" ascii wide nocase
    $mz = { 4D 5A }
    $pe = "PE\x00\x00"
  condition:
    $project and $mz and $pe
}
