rule OT_PowerShell_Dropper_On_EWS
{
  meta:
    author = "Liam Carvajal"
    description = "A PowerShell script on an engineering workstation that invokes expression evaluation and combines at least two loader behaviours (an encoded command, a remote download, or an in-memory assembly load), the shape of a dropper. Substrings such as 'iexplore.exe' and '-Encoding' are deliberately not treated as execution."
    date = "2026-11-04"
    attack_ics = "T0853"
    reference = "https://attack.mitre.org/techniques/T0853/"
    level = "high"
  strings:
    // A real invocation, not the 'IEX' inside 'iexplore.exe'. The keyword must
    // be followed by whitespace, an opening parenthesis or a variable.
    $iex = /(?i)\b(invoke-expression|iex)[ \t\r\n\(\$]/

    // An encoded command needs a base64-looking blob. '-Encoding UTF8' does not,
    // because the short form requires whitespace immediately after '-enc'.
    $enc_full = /(?i)-encodedcommand[ \t]+["']?[A-Za-z0-9+\/_-]{16,}={0,2}/
    $enc_short = /(?i)-enc[ \t]+["']?[A-Za-z0-9+\/_-]{16,}={0,2}/

    // Remote fetch primitives, and a shell pipe from curl/wget.
    $download = /(?i)(invoke-webrequest|downloadstring|downloadfile|net\.webclient)/
    $curl_pipe = /(?i)(curl|wget)[^\r\n|]{0,200}\|[ \t]*(sh|bash|powershell|pwsh|cmd)\b/

    // In-memory loader: assembly load or base64 decode followed by a load.
    $memload = /(?i)(\[reflection\.assembly\]\s*::\s*load|frombase64string[\s\S]{0,200}\bload\b)/
  condition:
    $iex and
    (
      (($enc_full or $enc_short) and ($download or $curl_pipe or $memload)) or
      ($download and $memload)
    )
}
