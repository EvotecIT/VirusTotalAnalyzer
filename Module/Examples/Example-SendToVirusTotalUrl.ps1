Import-Module .\VirusTotalAnalyzer.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

New-VirusScan -ApiKey $VTApi -Url 'evotec.pl'
New-VirusScan -ApiKey $VTApi -Url 'https://evotec.pl'