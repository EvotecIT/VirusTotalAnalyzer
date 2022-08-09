﻿Import-Module .\VirussoTotalo.psd1 -Force

$VTApi = Get-Content -LiteralPath "C:\Support\Important\VirusTotalApi.txt"

$T1 = Get-VirusReport -ApiKey $VTApi -FileHash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
$T2 = Get-VirusReport -ApiKey $VTApi -File 'C:\Support\GitHub\PSPublishModule\Releases\v0.9.47\PSPublishModule.psm1'
$T3 = Get-VirusReport -ApiKey $VTApi -DomainName 'evotec.xyz'
$T4 = Get-VirusReport -ApiKey $VTApi -IPAddress '1.1.1.1'
$T5 = Get-VirusReport -ApiKey $VTApi -Search "https://evotec.xyz"