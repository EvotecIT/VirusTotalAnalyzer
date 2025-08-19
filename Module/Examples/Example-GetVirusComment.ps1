Import-Module .\VirusTotalAnalyzer.psd1 -Force

$ApiKey = 'YOUR_API_KEY'

# Get the first 10 comments for a file by its SHA256 hash, skipping the first 5
Get-VirusComment -ApiKey $ApiKey -ResourceType File -Id 'FILE_SHA256' -First 10 -Skip 5

