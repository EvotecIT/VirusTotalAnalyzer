Import-Module .\VirusTotalAnalyzer.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

$Items = "C:\Users\przemyslaw.klys\Downloads\amd-software-adrenalin-edition-24.10.1-minimalsetup-241017_web.exe"

# Submit file to scan
$Output = New-VirusScan -ApiKey $VTApi -Verbose -File $Items
$Output | Format-List

Start-Sleep -Seconds 120

# Since the output will return scan ID we can use it to get the report
$OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
$OutputScan | Format-List
$OutputScan.Meta | Format-List
$OutputScan.Data | Format-List