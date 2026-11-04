rule OT_PowerShell_Dropper_On_EWS
{
  meta:
    author = "Liam Carvajal"
    description = "A PowerShell script on an engineering workstation that combines encoded or remote execution with an in-memory loader or a shell pipe, the shape of a dropper."
    date = "2026-11-04"
    attack_ics = "T0853"
    reference = "https://attack.mitre.org/techniques/T0853/"
    level = "high"
  strings:
    $enc = "-enc" ascii nocase
    $download = "Invoke-WebRequest" ascii nocase
    $iex = "IEX" ascii nocase
    $pipe = "| sh" ascii nocase
  condition:
    ($enc or $download) and ($iex or $pipe)
}
