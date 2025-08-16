Import-Module .\VirusTotalAnalyzer.psd1 -Force

$ApiKey = 'YOUR_API_KEY'

# Cast a malicious vote for a file
New-VirusVote -ApiKey $ApiKey -ResourceType File -Id 'FILE_SHA256' -Verdict Malicious
