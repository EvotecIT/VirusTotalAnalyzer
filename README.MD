<p align="center">
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img src="https://img.shields.io/powershellgallery/v/VirusTotalAnalyzer.svg"></a>
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img src="https://img.shields.io/powershellgallery/vpre/VirusTotalAnalyzer.svg?label=powershell%20gallery%20preview&colorB=yellow"></a>
  <a href="https://github.com/EvotecIT/VirusTotalAnalyzer"><img src="https://img.shields.io/github/license/EvotecIT/VirusTotalAnalyzer.svg"></a>
</p>

<p align="center">
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img src="https://img.shields.io/powershellgallery/p/VirusTotalAnalyzer.svg"></a>
  <a href="https://github.com/EvotecIT/VirusTotalAnalyzer"><img src="https://img.shields.io/github/languages/top/evotecit/VirusTotalAnalyzer.svg"></a>
  <a href="https://github.com/EvotecIT/VirusTotalAnalyzer"><img src="https://img.shields.io/github/languages/code-size/evotecit/VirusTotalAnalyzer.svg"></a>
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img src="https://img.shields.io/powershellgallery/dt/VirusTotalAnalyzer.svg"></a>
</p>

<p align="center">
  <a href="https://twitter.com/PrzemyslawKlys"><img src="https://img.shields.io/twitter/follow/PrzemyslawKlys.svg?label=Twitter%20%40PrzemyslawKlys&style=social"></a>
  <a href="https://evotec.xyz/hub"><img src="https://img.shields.io/badge/Blog-evotec.xyz-2A6496.svg"></a>
  <a href="https://www.linkedin.com/in/pklys"><img src="https://img.shields.io/badge/LinkedIn-pklys-0077B5.svg?logo=LinkedIn"></a>
</p>

# VirusTotalAnalyzer PowerShell Module

**VirusTotalAnalyzer** is very small PowerShell module that helps with submiting files to VirusTotal service and getting results.
It allowws to check if file is infected or not and also to get information about file.
You can also request information about URL, Domain or IPAddress.


You can read about it on my blog:

- [Working with Virus Total from PowerShell](https://evotec.xyz/working-with-virustotal-from-powershell/)

### Getting information from VirusTotal
After installation of module you can use it like this:

```powershell
Import-Module VirusTotalAnalyzer -Force

# API KEY can be found once you register to Virus Total service (it's free)
$VTApi = 'APIKEY'

$T1 = Get-VirusReport -ApiKey $VTApi -Hash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
$T2 = Get-VirusReport -ApiKey $VTApi -File "$PSScriptRoot\Submisions\TestFile.txt"
$T3 = Get-VirusReport -ApiKey $VTApi -DomainName 'evotec.xyz'
$T4 = Get-VirusReport -ApiKey $VTApi -IPAddress '1.1.1.1'
$T5 = Get-VirusReport -ApiKey $VTApi -Search "https://evotec.xyz"
```

Each variable from above delivers additional information about given request.

Output first level
```
data
----
@{attributes=; type=file; id=bff77eecbb2f7da25ecbc9d9673e5dc1db68dcc68fd76d006e836f9ac61c547e; links=}
```


Output second level
```
attributes
----------
@{type_description=Powershell; tlsh=T10404B65A7D05522320B36B76E8A78008FF77423B4254111978ECD6C87F75928D3BAFEA; vhash=029198501f8f46256cb0cf2e4fbb8ce7; trid=System.Object[]; crowdsourced_yara_results=System.Object[]; names=System.Object[]; last_modification_date=1659953097; type_tag=powers...
```

Output third level
```
attributes : @{type_description=Powershell; tlsh=T10404B65A7D05522320B36B76E8A78008FF77423B4254111978ECD6C87F75928D3BAFEA; vhash=029198501f8f46256cb0cf2e4fbb8ce7; trid=System.Object[]; crowdsourced_yara_results=System.Object[]; names=System.Object[]; last_modification_date=1659953097;
             type_tag=powershell; times_submitted=2; total_votes=; size=184182; type_extension=ps1; last_submission_date=1659903352; last_analysis_results=; sandbox_verdicts=; sha256=bff77eecbb2f7da25ecbc9d9673e5dc1db68dcc68fd76d006e836f9ac61c547e; tags=System.Object[];
             last_analysis_date=1659903352; unique_sources=2; first_submission_date=1659862256; ssdeep=3072:wMxUx42PfUYYxlQ7uZtAcI5GCy23KV9syb0wqV:wa2G923K6V; md5=e3c925286ccafd07fb61bd6a12a2ee94; sha1=79fc6a99468f83c7f98e58fdbb811cd95a153567; magic=UTF-8 Unicode (with BOM) English text,
             with very long lines, with CRLF line terminators; powershell_info=; last_analysis_stats=; meaningful_name=PSPublishModule.psm1; reputation=0}
type       : file
id         : bff77eecbb2f7da25ecbc9d9673e5dc1db68dcc68fd76d006e836f9ac61c547e
links      : @{self=https://www.virustotal.com/api/v3/files/bff77eecbb2f7da25ecbc9d9673e5dc1db68dcc68fd76d006e836f9ac61c547e}
```

Output fourth level

```
type_description          : Powershell
tlsh                      : T10404B65A7D05522320B36B76E8A78008FF77423B4254111978ECD6C87F75928D3BAFEA
vhash                     : 029198501f8f46256cb0cf2e4fbb8ce7
trid                      : {@{file_type=Text - UTF-8 encoded; probability=100.0}}
crowdsourced_yara_results : {@{description=This signature fires on the presence of Base64 encoded URI prefixes (http:// and https://) across any file. The simple presence of such strings is not inherently an indicator of malicious content, but is worth further investigation.;
                            source=https://github.com/InQuest/yara-rules-vt; author=InQuest Labs; ruleset_name=Base64_Encoded_URL; rule_name=Base64_Encoded_URL; ruleset_id=0122bae1e9}, @{description=This signature detects the presence of a number of Windows API functionality often seen
                            within embedded executables. When this signature alerts on an executable, it is not an indication of malicious behavior. However, if seen firing in other file types, deeper investigation may be warranted.; source=https://github.com/InQuest/yara-rules-vt;
                            author=InQuest Labs; ruleset_name=Windows_API_Function; rule_name=Windows_API_Function; ruleset_id=0122a7f913}}
names                     : {PSPublishModule.psm1}
last_modification_date    : 1659953097
type_tag                  : powershell
times_submitted           : 2
total_votes               : @{harmless=0; malicious=0}
size                      : 184182
type_extension            : ps1
last_submission_date      : 1659903352
last_analysis_results     : @{Bkav=; Lionic=; tehtris=; DrWeb=; MicroWorld-eScan=; FireEye=; CAT-QuickHeal=; ALYac=; Malwarebytes=; VIPRE=; Paloalto=; Sangfor=; K7AntiVirus=; Alibaba=; K7GW=; Trustlook=; BitDefenderTheta=; VirIT=; Cyren=; SymantecMobileInsight=; Symantec=; Elastic=;
                            ESET-NOD32=; APEX=; TrendMicro-HouseCall=; Avast=; ClamAV=; Kaspersky=; BitDefender=; NANO-Antivirus=; SUPERAntiSpyware=; Tencent=; Ad-Aware=; Emsisoft=; Comodo=; F-Secure=; Baidu=; Zillya=; TrendMicro=; McAfee-GW-Edition=; SentinelOne=; Trapmine=; CMC=;
                            Sophos=; Ikarus=; GData=; Jiangmin=; Webroot=; Avira=; Antiy-AVL=; Kingsoft=; Gridinsoft=; Arcabit=; ViRobot=; ZoneAlarm=; Avast-Mobile=; Microsoft=; Cynet=; BitDefenderFalx=; AhnLab-V3=; Acronis=; McAfee=; MAX=; VBA32=; Cylance=; Zoner=; Rising=; Yandex=;
                            TACHYON=; MaxSecure=; Fortinet=; Cybereason=; Panda=; CrowdStrike=}
sandbox_verdicts          : @{C2AE=}
sha256                    : bff77eecbb2f7da25ecbc9d9673e5dc1db68dcc68fd76d006e836f9ac61c547e
tags                      : {powershell}
last_analysis_date        : 1659903352
unique_sources            : 2
first_submission_date     : 1659862256
ssdeep                    : 3072:wMxUx42PfUYYxlQ7uZtAcI5GCy23KV9syb0wqV:wa2G923K6V
md5                       : e3c925286ccafd07fb61bd6a12a2ee94
sha1                      : 79fc6a99468f83c7f98e58fdbb811cd95a153567
magic                     : UTF-8 Unicode (with BOM) English text, with very long lines, with CRLF line terminators
powershell_info           : @{dotnet_calls=System.Object[]; cmdlets=System.Object[]; functions=System.Object[]; cmdlets_alias=System.Object[]; ps_variables=System.Object[]}
last_analysis_stats       : @{harmless=0; type-unsupported=15; suspicious=0; confirmed-timeout=0; timeout=0; failure=0; malicious=0; undetected=59}
meaningful_name           : PSPublishModule.psm1
reputation                : 0
```

Depending on which type of object we're working with the results may be diferrent.

### Sending a file or url to Virus Total

To send Url to Virus Total

```powershell
Import-Module VirusTotalAnalyzer -Force

$VTApi = 'APIKEY'

New-VirusScan -ApiKey $VTApi -Url 'evotec.pl'
New-VirusScan -ApiKey $VTApi -Url 'https://evotec.pl'
```

To send file to Virus Total

```powershell
Import-Module VirusTotalAnalyzer -Force

$VTApi = 'APIKEY'

# Submit file to scan
$Output = New-VirusScan -ApiKey $VTApi -File "$PSScriptRoot\Submisions\TestFile.txt"
$Output | Format-List

Start-Sleep -Seconds 60

# Since the output will return scan ID we can use it to get the report
$OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
$OutputScan | Format-List
$OutputScan.Meta | Format-List
$OutputScan.Data | Format-List
```

`New-VirusScan` will return an object which then can be verified via `Get-VirusReport`.
Give it some time before checking for results, as it takes time to scan the file.
`New-VirusScan` also provides a way to rescan a file that was already submitted.
You can do so using `Hash` or `FileHash` paramater.

Once file is finally scanned it will be available using `Get-VirusTotal` with one of the available options.

## To install

```powershell
Install-Module -Name VirusTotalAnalyzer -AllowClobber -Force
```

Force and AllowClobber aren't necessary, but they do skip errors in case some appear.

## And to update

```powershell
Update-Module -Name VirusTotalAnalyzer
```

That's it. Whenever there's a new version, you run the command, and you can enjoy it. Remember that you may need to close, reopen PowerShell session if you have already used module before updating it.

**The essential thing** is if something works for you on production, keep using it till you test the new version on a test computer. I do changes that may not be big, but big enough that auto-update may break your code. For example, small rename to a parameter and your code stops working! Be responsible!