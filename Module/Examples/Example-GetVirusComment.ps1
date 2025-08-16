Import-Module .\VirusTotalAnalyzer.psd1 -Force

$ApiKey = 'YOUR_API_KEY'

# Get comments for a file by its SHA256 hash
Get-VirusComment -ApiKey $ApiKey -ResourceType File -Id 'FILE_SHA256'
