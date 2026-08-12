<p align="center">
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img src="https://img.shields.io/powershellgallery/v/VirusTotalAnalyzer.svg"></a>
  <a href="https://github.com/EvotecIT/VirusTotalAnalyzer"><img src="https://img.shields.io/github/license/EvotecIT/VirusTotalAnalyzer.svg"></a>
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img src="https://img.shields.io/powershellgallery/dt/VirusTotalAnalyzer.svg"></a>
</p>

# VirusTotalAnalyzer

VirusTotalAnalyzer is a typed .NET client and compiled PowerShell module for the documented VirusTotal API v3. Its main job is the everyday VirusTotal workflow: submit a file or URL, wait for analysis, and retrieve reports for files, URLs, domains, and IP addresses.

The library targets .NET Framework 4.7.2, .NET 8, and .NET 10. The PowerShell module supports Windows PowerShell 5.1 and PowerShell 7+.

## Public API usage

Create a free VirusTotal Community account and store its API key in the `VIRUSTOTAL_API_KEY` environment variable:

```powershell
$env:VIRUSTOTAL_API_KEY = 'your-api-key'
Import-Module VirusTotalAnalyzer
```

The key can still be supplied explicitly with `-ApiKey`, or an existing `IVirusTotalClient` can be passed with `-Client`.

Submit a file or URL and wait for the completed analysis:

```powershell
$fileAnalysis = New-VirusScan -File '.\sample.exe' -Wait
$urlAnalysis  = New-VirusScan -Url 'https://example.com' -Wait
```

The default 20-second polling interval is deliberately conservative for the public API. It can be changed when the account has a different licensed limit:

```powershell
New-VirusScan -File '.\sample.exe' -Wait -TimeoutSeconds 600 -PollingIntervalSeconds 30
```

Retrieve existing reports without submitting content:

```powershell
Get-VirusReport -Hash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
Get-VirusReport -File '.\sample.exe'
Get-VirusReport -Url 'https://example.com'
Get-VirusReport -DomainName 'example.com'
Get-VirusReport -IPAddress '1.1.1.1'
```

`Get-VirusUser -Id <user-id>` returns the documented user object, including visible quota and privilege dictionaries. VirusTotal only returns private account fields when the caller is entitled to see them.

VirusTotal currently limits the Public API to 500 requests per day and 4 requests per minute. Its terms also prohibit use of the Public API in commercial products or services and in business workflows that do not contribute new files. Use a licensed VirusTotal service for those scenarios. See [Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api).

## .NET usage

```csharp
using VirusTotalAnalyzer;

using var client = VirusTotalClient.Create(
    Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY")
        ?? throw new InvalidOperationException("VIRUSTOTAL_API_KEY is not set."));

var submission = await client.ScanFileAsync("sample.exe", cancellationToken: cancellationToken);
var analysis = submission is null
    ? null
    : await client.WaitForAnalysisCompletionAsync(
        submission.Id,
        TimeSpan.FromMinutes(5),
        cancellationToken: cancellationToken);
```

The same client exposes comments, votes, relationships, graphs, collections, Intelligence search and hunting, private scanning, feeds, ZIP jobs, and VirusTotal Monitor. Licensed endpoints remain available for entitled accounts but are not part of the free-key workflow.

## VirusTotal Monitor

Monitor is a licensed publisher workflow, not an antivirus verdict from the Public API. The upload API streams file content, verifies the remote SHA-256 by default, and supports versioned destination paths:

```powershell
Send-VirusTotalMonitorFile `
    -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY `
    -File '.\MyProduct.exe' `
    -Path '/MyProduct/1.2.3/win-x64/MyProduct.exe' `
    -Details 'Signed release artifact'

Get-VirusTotalMonitorItem -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY -List -All
Get-VirusTotalMonitorEvent -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY -All
Get-VirusTotalMonitorStatistics -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY
```

## Install

```powershell
Install-Module VirusTotalAnalyzer -Scope CurrentUser
```

Review [V3-MIGRATION.md](V3-MIGRATION.md) before upgrading code that used the pre-release .NET API surface.
