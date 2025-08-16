Import-Module .\VirusTotalAnalyzer.psd1 -Force

$ApiKey = 'YOUR_API_KEY'

# Retrieve information about a VirusTotal user
Get-VirusUser -ApiKey $ApiKey -Id 'USERNAME'
