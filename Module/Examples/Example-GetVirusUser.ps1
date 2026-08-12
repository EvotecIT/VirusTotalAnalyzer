Import-Module .\VirusTotalAnalyzer.psd1 -Force

$env:VIRUSTOTAL_API_KEY = 'YOUR_API_KEY'
$env:VIRUSTOTAL_USER_ID = 'YOUR_USER_ID'

# Retrieve the current configured account and its visible quotas.
Get-VirusAccount
Get-VirusAccount -Quota
