<p align="center">
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img alt="PowerShell Gallery version" src="https://img.shields.io/powershellgallery/v/VirusTotalAnalyzer.svg"></a>
  <a href="https://www.nuget.org/packages/VirusTotalAnalyzer"><img alt="NuGet version" src="https://img.shields.io/nuget/v/VirusTotalAnalyzer.svg"></a>
  <a href="https://github.com/EvotecIT/VirusTotalAnalyzer"><img alt="License" src="https://img.shields.io/github/license/EvotecIT/VirusTotalAnalyzer.svg"></a>
  <a href="https://www.powershellgallery.com/packages/VirusTotalAnalyzer"><img alt="PowerShell Gallery downloads" src="https://img.shields.io/powershellgallery/dt/VirusTotalAnalyzer.svg"></a>
  <a href="https://www.nuget.org/packages/VirusTotalAnalyzer"><img alt="NuGet downloads" src="https://img.shields.io/nuget/dt/VirusTotalAnalyzer.svg"></a>
</p>

# VirusTotalAnalyzer - VirusTotal API v3 for .NET and PowerShell

VirusTotalAnalyzer is a typed .NET client and compiled PowerShell module for the VirusTotal API v3. It supports everyday Community API workflows such as looking up reports and submitting files or URLs, as well as licensed features including private analysis, Intelligence, hunting, feeds, ZIP jobs, and VirusTotal Monitor publisher workflows.

The .NET library targets .NET Framework 4.7.2, .NET 8, and .NET 10. The PowerShell module supports Windows PowerShell 5.1 and PowerShell 7.4 or later on Windows, Linux, and macOS.

## Packages

| Surface | Package | Install |
| --- | --- | --- |
| .NET library | [VirusTotalAnalyzer on NuGet](https://www.nuget.org/packages/VirusTotalAnalyzer) | `dotnet add package VirusTotalAnalyzer` |
| PowerShell module | [VirusTotalAnalyzer on PowerShell Gallery](https://www.powershellgallery.com/packages/VirusTotalAnalyzer) | `Install-Module VirusTotalAnalyzer -Scope CurrentUser` |

## What it supports

| Capability | .NET | PowerShell | Access |
| --- | :---: | :---: | --- |
| File, URL, domain, IP address, and analysis reports | Yes | Yes | Community API |
| File and URL submission with completion polling | Yes | Yes | Community API and account quota |
| Reanalysis | Files, URLs, domains, and IP addresses | Files | Endpoint and account dependent |
| Quota-aware batches with spacing, retry, caching, and duplicate-request suppression | Yes | Yes | Community API friendly |
| Domain and IP relationships, including resolutions, historical WHOIS, certificates, and related files | Yes | Yes | Relationship and account dependent |
| Comments, votes, users, privileges, and quotas | Yes | Selected cmdlets | Endpoint and account dependent |
| File behavior, sandbox summaries, artifacts, and signed downloads | Yes | - | Usually licensed |
| Graphs, graph permissions, and collections | Yes | - | Usually licensed |
| Public IOC search | Yes | Yes | Community API |
| Intelligence search, Livehunt, Retrohunt, YARA rulesets, IoC Stream, private analysis, feeds, and ZIP jobs | Yes | - | Licensed services |
| VirusTotal Monitor uploads, folders, items, events, statistics, and configuration | Yes | Yes | Monitor publisher entitlement |
| VirusTotal Monitor downloads | Yes | - | Monitor publisher entitlement |

The library exposes a larger API than the compiled PowerShell module. PowerShell focuses on common reporting, submission, community, relationship, account, and Monitor workflows; use the .NET client for the complete typed surface.

## Authentication and API access

Create a VirusTotal Community account and obtain an API key. PowerShell commands use `VIRUSTOTAL_API_KEY` when neither `-ApiKey` nor an existing `-Client` is supplied:

```powershell
$env:VIRUSTOTAL_API_KEY = 'your-api-key'
Import-Module VirusTotalAnalyzer
```

.NET callers pass the key when creating the client:

```csharp
using VirusTotalAnalyzer;

using var client = VirusTotalClient.Create(
    Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY")
        ?? throw new InvalidOperationException("VIRUSTOTAL_API_KEY is not set."));
```

Do not commit API keys. VirusTotalAnalyzer confines the key to authenticated VirusTotal API and upload requests. It does not forward the key to signed download URLs, include it in upload results, or write it to request diagnostics.

The VirusTotal Public API currently allows 500 requests per day and four requests per minute. It must not be used in commercial products or services, or in business workflows that do not contribute new files. See VirusTotal's [Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api) guidance before building an automated workflow.

## PowerShell usage

### Look up reports and verdicts

`Get-VirusReport` accepts hashes, files, URLs, domains, IP addresses, analysis IDs, and public IOC or comment-tag searches:

```powershell
Get-VirusReport -Hash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
Get-VirusReport -File '.\sample.exe'
Get-VirusReport -Url 'https://example.com'
Get-VirusReport -DomainName 'example.com'
Get-VirusReport -IPAddress '1.1.1.1'
Get-VirusReport -AnalysisId $analysisId
Get-VirusReport -Search 'example.com'
```

Pass arrays or pipeline input for batches. `-Summary` returns a concise verdict while retaining the complete report in its `Report` property:

```powershell
$verdicts = Get-VirusReport -Hash $hashes -Summary
$verdicts | Select-Object Id, Verdict, Malicious, Suspicious, Reputation, LastAnalysisDate, Permalink

$fullReport = $verdicts[0].Report
```

Batch requests preserve input order and duplicate output entries while avoiding duplicate API requests. They cache successful reports for five minutes, retry `429` responses using `Retry-After`, and start requests 20 seconds apart by default. Change `-MinimumIntervalSeconds`, `-CacheSeconds`, or `-MaxRetries` only to match the quota of the account being used.

### Submit files and URLs

Submit content and optionally wait for the completed analysis:

```powershell
$fileAnalysis = New-VirusScan -File '.\sample.exe' -Wait
$urlAnalysis = New-VirusScan -Url 'https://example.com' -Wait

# Reanalyse an existing file by its hash.
$analysis = New-VirusScan -Hash $sha256 -Wait
```

The default polling interval is 20 seconds. Licensed accounts can use a different interval when their quota permits it:

```powershell
New-VirusScan -File '.\sample.exe' -Wait -TimeoutSeconds 600 -PollingIntervalSeconds 10
```

### Explore relationships

The PowerShell surface provides typed, paged relationships for domains and IP addresses:

```powershell
Get-VirusRelationship -DomainName 'example.com' -Relationship Resolutions
Get-VirusRelationship -DomainName 'example.com' -Relationship HistoricalWhois
Get-VirusRelationship -DomainName 'example.com' -Relationship HistoricalSslCertificates
Get-VirusRelationship -DomainName 'example.com' -Relationship CommunicatingFiles -Limit 10

Get-VirusRelationship -IPAddress '1.1.1.1' -Relationship Resolutions
Get-VirusRelationship -IPAddress '1.1.1.1' -Relationship ReferrerFiles -Limit 10
```

Use `-Page` when the response metadata and cursor are needed for manual pagination.

### Work with community and account data

```powershell
Get-VirusComment -ResourceType File -Id $sha256 -Limit 10
New-VirusVote -ResourceType File -Id $sha256 -Verdict Malicious

$env:VIRUSTOTAL_USER_ID = 'your-user-id'
Get-VirusAccount
Get-VirusAccount -Quota
```

`Get-VirusAccount` is an alias for `Get-VirusUser`. The user ID is separate from the API key; the command never substitutes the key into `/users/{id}`.

### Use VirusTotal Monitor

VirusTotal Monitor is a licensed publisher workflow, not an immediate antivirus verdict. Uploads are streamed, large files use the dedicated upload endpoint, and the remote SHA-256 is verified by default:

```powershell
$receipt = Send-VirusTotalMonitorFile `
    -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY `
    -File '.\MyProduct.exe' `
    -Path '/MyProduct/1.2.3/win-x64/MyProduct.exe' `
    -Details 'Signed release artifact'

$receipt | Select-Object MonitorId, RemotePath, LocalSha256, RemoteSha256
```

Use versioned paths to preserve earlier releases. To replace an item intentionally, use `-ExistingItemId` instead of `-Path`.

```powershell
$monitorKey = $env:VIRUSTOTAL_MONITOR_API_KEY
New-VirusTotalMonitorFolder -ApiKey $monitorKey -Path '/MyProduct/1.2.3/'
Get-VirusTotalMonitorItem -ApiKey $monitorKey -List -Tag new-detections -All
Get-VirusTotalMonitorEvent -ApiKey $monitorKey -Filter 'action:DETECTED' -All
Get-VirusTotalMonitorStatistics -ApiKey $monitorKey
Set-VirusTotalMonitorItem -ApiKey $monitorKey -Id $itemId -Details 'Signed release build'
Remove-VirusTotalMonitorItem -ApiKey $monitorKey -Id $itemId -Confirm
```

### Available cmdlets

| Cmdlet | Purpose |
| --- | --- |
| `Get-VirusReport` | Retrieve reports for files, URLs, domains, IP addresses, or analyses |
| `New-VirusScan` | Submit a file or URL, reanalyse a file by hash or local path, and optionally wait for completion |
| `Get-VirusRelationship` | Retrieve typed domain and IP relationship data |
| `Get-VirusComment` | Read comments attached to a VirusTotal object |
| `New-VirusVote` | Add a harmless or malicious community vote |
| `Get-VirusUser` / `Get-VirusAccount` | Read user, privilege, and quota information |
| `Send-VirusTotalMonitorFile` | Upload and verify a publisher artifact |
| `New-VirusTotalMonitorFolder` | Create a Monitor folder |
| `Get-VirusTotalMonitorItem` | Retrieve or enumerate Monitor items |
| `Set-VirusTotalMonitorItem` | Update Monitor item details |
| `Remove-VirusTotalMonitorItem` | Delete a Monitor item |
| `Get-VirusTotalMonitorEvent` | Retrieve or enumerate Monitor events |
| `Get-VirusTotalMonitorStatistics` | Retrieve Monitor detection statistics |

All cmdlets accept either `-ApiKey` or an existing `IVirusTotalClient` through `-Client`, which lets several commands share one configured client.

## .NET usage

### Look up reports and typed verdicts

```csharp
var report = await client.GetFileReportAsync(
    sha256,
    cancellationToken: cancellationToken);

if (report is not null)
{
    var verdict = report.ToVerdict();
    Console.WriteLine($"{verdict.Id}: {verdict.Verdict} ({verdict.Malicious} malicious)");
}
```

Equivalent typed methods are available for URLs, domains, IP addresses, and analyses. URL strings can be converted to VirusTotal's URL identifier with `VirusTotalClientExtensions.GetUrlId`.

### Submit and wait for analysis

```csharp
var submission = await client.ScanFileAsync(
    "sample.exe",
    cancellationToken: cancellationToken);

var completed = submission is null
    ? null
    : await client.WaitForAnalysisCompletionAsync(
        submission.Id,
        TimeSpan.FromMinutes(5),
        cancellationToken: cancellationToken);
```

Use `ScanUrlAsync`, `SubmitUrlAsync`, or the stream-based `SubmitFileAsync` overloads for other submission shapes. Reanalysis methods are available for files, hashes, URLs, domains, and IP addresses.

### Run quota-aware batches

```csharp
var reports = await client.GetFileReportsBatchAsync(
    hashes,
    cancellationToken: cancellationToken);

var verdicts = reports.Select(report => report.ToVerdict()).ToArray();
```

`VirusTotalBatchOptions` controls request spacing, cache duration, and rate-limit retries. The explicit `*BatchAsync` methods opt into quota coordination; singular and ordinary plural report methods remain direct API calls.

### Query relationships and behavior

```csharp
var whois = await client.GetDomainHistoricalWhoisAsync(
    "example.com",
    cancellationToken: cancellationToken);

var resolutions = await client.GetIpAddressResolutionsAsync(
    "1.1.1.1",
    cancellationToken: cancellationToken);

var behavior = await client.GetFileBehaviorSummaryAsync(
    sha256,
    cancellationToken: cancellationToken);
```

The .NET client also exposes paged methods for manual cursor handling and `IAsyncEnumerable<T>` where streaming across pages is useful.

### Use community and account APIs

```csharp
using VirusTotalAnalyzer.Models;

await client.AddCommentAsync(
    ResourceType.File,
    sha256,
    "Reviewed by the incident response team.",
    cancellationToken);

await client.VoteAsync(
    ResourceType.File,
    sha256,
    VoteVerdict.Malicious,
    cancellationToken);

var user = await client.GetUserAsync(userId, cancellationToken);
```

### Use advanced and licensed APIs

The same typed client includes:

- public IOC and tag search through `SearchAsync`;
- advanced corpus search through `SearchIntelligenceAsync`;
- Livehunt notifications, Retrohunt jobs, and YARA rulesets;
- IoC Stream and compressed minute or hourly feeds;
- private file submission with `PrivateFileUploadOptions`;
- file behavior downloads for HTML, EVTX, PCAP, and memory dumps;
- graphs, graph permissions, collections, and collection relationships;
- asynchronous ZIP creation and download jobs.

These methods do not bypass VirusTotal licensing. An available method can still return an authorization error when the API key lacks the required service or relationship entitlement.

### Register and track Monitor artifacts

```csharp
using VirusTotalAnalyzer.Models;

var receipt = await client.UploadMonitorFileAsync(
    artifactPath,
    new MonitorUploadOptions
    {
        Path = $"/MyProduct/{version}/win-x64/MyProduct.exe",
        Details = "Signed release artifact",
        VerifySha256 = true,
        VerificationTimeout = TimeSpan.FromMinutes(2)
    },
    cancellationToken);

Console.WriteLine($"Verified {receipt.RemotePath}: {receipt.RemoteSha256}");
```

Query large Monitor collections without managing cursors manually:

```csharp
await foreach (var item in client.EnumerateMonitorItemsAsync(
    MonitorItemFilter.ByTags("new-detections"),
    cancellationToken: cancellationToken))
{
    Console.WriteLine($"{item.Attributes.Path}: {item.Attributes.LastDetectionsCount}");
}

await foreach (var monitorEvent in client.EnumerateMonitorEventsAsync(
    filter: "action:DETECTED",
    cancellationToken: cancellationToken))
{
    Console.WriteLine($"{monitorEvent.Timestamp:u} {monitorEvent.Subject}");
}
```

Upload and SHA-256 verification prove that the intended artifact was registered. Detections, resolved events, and statistics arrive later as Monitor processes and periodically rescans the publisher collection.

### Configure custom HTTP transports

`VirusTotalClient.Create` is the simplest and safest setup. For a proxy, client certificate, custom DNS behavior, or deterministic test transport, pass separate authenticated API and unauthenticated download handlers:

```csharp
using System.Net.Http;

using var apiHandler = new HttpClientHandler { AllowAutoRedirect = false };
using var downloadHandler = new HttpClientHandler { AllowAutoRedirect = false };
using var client = new VirusTotalClient(
    apiKey,
    apiHandler,
    downloadHandler,
    disposeHandlers: false);
```

Automatic redirects must be disabled on both handler chains. This lets the library intercept signed-download redirects, enforce HTTPS and redirect limits, and switch to the unauthenticated transport before following the signed URL.

## Compatibility and migration

| Component | Supported runtimes |
| --- | --- |
| .NET library | .NET Framework 4.7.2, .NET 8, .NET 10 |
| PowerShell module | Windows PowerShell 5.1, PowerShell 7.4 or later |
| Operating systems | Windows, Linux, macOS; .NET Framework is Windows-only |

Review the [API v3 migration guide](https://github.com/EvotecIT/VirusTotalAnalyzer/blob/master/MIGRATION.md) when upgrading code written against an earlier prerelease surface.

## Project links

- [VirusTotal API v3 documentation](https://docs.virustotal.com/reference/overview)
- [Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)
- [NuGet package](https://www.nuget.org/packages/VirusTotalAnalyzer)
- [PowerShell Gallery module](https://www.powershellgallery.com/packages/VirusTotalAnalyzer)
- [Source code and issues](https://github.com/EvotecIT/VirusTotalAnalyzer)
