Start-Process iexplore.exe "https://intranet.example/portal"
Get-Process iexplore | Select-Object Id, MainWindowTitle
