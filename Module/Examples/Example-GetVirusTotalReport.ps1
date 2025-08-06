Import-Module .\VirusTotalAnalyzer.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

$T1 = Get-VirusReport -ApiKey $VTApi -Hash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
$T1
$T2 = Get-VirusReport -ApiKey $VTApi -Hash '44676ad570f565608ddd6759532c3ae7b1e1a97d'
$T2
$T3 = Get-VirusReport -ApiKey $VTApi -File "$PSScriptRoot\Submisions\TestFile.txt"
$T3
$T4 = Get-VirusReport -ApiKey $VTApi -DomainName 'evotec.xyz'
$T4
$T5 = Get-VirusReport -ApiKey $VTApi -IPAddress '1.1.1.1'
$T5
$T6 = Get-VirusReport -ApiKey $VTApi -Search "https://evotec.xyz"
$T6