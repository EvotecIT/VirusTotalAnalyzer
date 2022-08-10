Import-Module .\VirusTotalAnalyzer.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

# Submit file to scan
$Output = New-VirusScan -ApiKey $VTApi -File "$PSScriptRoot\Submisions\TestFile.txt"
$Output | Format-List

# Since the output will return scan ID we can use it to get the report
$OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
$OutputScan | Format-List
$OutputScan.Meta | Format-List
$OutputScan.Data | Format-List