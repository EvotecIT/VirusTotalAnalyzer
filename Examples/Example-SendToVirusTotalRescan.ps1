Import-Module .\VirusTotalAnalyzer.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

# Submit file hash to rescan from existing file (doesn't sends the file)
$Output = New-VirusScan -ApiKey $VTApi -FileHash "$PSScriptRoot\Submisions\TestFile.txt"
$Output | Format-List

# Submit hash to rescan
$Output = New-VirusScan -ApiKey $VTApi -Hash "ThisHashHasToExistsOnVirusTotal"
$Output | Format-List