Import-Module .\VirusTotalAnalyzer.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

$Items = Get-ChildItem -LiteralPath "C:\Users\przemyslaw.klys\Documents\WindowsPowerShell\Modules\PSWriteHTML\Resources\CSS" -Include "*.css" -File -Recurse

# Submit file to scan
$Output = $Items | New-VirusScan -ApiKey $VTApi -Verbose
$Output | Format-List

Start-Sleep -Seconds 120

# Since the output will return scan ID we can use it to get the report
$OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
$OutputScan | Format-List
$OutputScan.Meta | Format-List
$OutputScan.Data | Format-List