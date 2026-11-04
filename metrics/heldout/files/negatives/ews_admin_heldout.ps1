Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, CPU
Get-ChildItem C:\Temp | Sort-Object LastWriteTime
