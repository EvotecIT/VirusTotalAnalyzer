Import-Module .\VirusTotal.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

Invoke-VirusScan -ApiKey $VTApi -Url 'evotec.pl'
Invoke-VirusScan -ApiKey $VTApi -Url 'https://evotec.pl'