powershell.exe -Encoding UTF8 -File C:\Scripts\DailyHealth.ps1
$report = Get-Content C:\Temp\health.txt
$report | Set-Content -Encoding UTF8 C:\Temp\health-utf8.txt
