# VirusTotalAnalyzer

VirusTotalAnalyzer is a typed .NET client for VirusTotal API v3. It covers reports, submissions, relationships, Intelligence endpoints, and the VirusTotal Monitor publisher workflow.

The package targets .NET Framework 4.7.2, .NET 8, and .NET 10.

```shell
dotnet add package VirusTotalAnalyzer
```

## Create a client

```csharp
using VirusTotalAnalyzer;

using var client = VirusTotalClient.Create(
    Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY")
        ?? throw new InvalidOperationException("VIRUSTOTAL_API_KEY is not set."));

var report = await client.GetFileReportAsync(sha256, cancellationToken: cancellationToken);
```

`VirusTotalClient.Create` applies a bounded HTTP timeout. Applications that already manage `HttpClient` lifetime can pass their own client to the `VirusTotalClient` constructor.

## Register a publisher artifact with VirusTotal Monitor

Monitor uploads are different from ordinary public file submissions. They require a VirusTotal account with the Monitor publisher entitlement.

```csharp
using VirusTotalAnalyzer.Models;

var receipt = await client.UploadMonitorFileAsync(
    artifactPath,
    new MonitorUploadOptions
    {
        Path = $"/TestimoX/{version}/win-x64/TestimoX.CLI.exe",
        Details = "Signed TestimoX release artifact",
        VerifySha256 = true,
        VerificationTimeout = TimeSpan.FromMinutes(2)
    },
    cancellationToken);

Console.WriteLine($"Verified {receipt.RemotePath}: {receipt.RemoteSha256}");
```

The upload streams file content, calculates the local SHA-256, selects the large-file upload endpoint above 32 MB, and fails if the remote hash disagrees or Monitor does not expose a hash before the verification timeout. Set `VerifySha256` to `false` only when the caller intentionally accepts an unverified registration receipt; an upload receipt is not a clean antivirus verdict.

Use versioned destination paths instead of replacing earlier releases. To intentionally replace an existing item, set `ExistingItemId` instead of `Path`.

## Query Monitor state

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

var statistics = await client.GetMonitorStatisticsAsync(cancellationToken: cancellationToken);
```

Monitor is asynchronous reputation tracking. Upload and hash verification prove that the intended artifact was registered; detections, resolved events, and statistics arrive as Monitor processes and periodically rescans the publisher collection.

## PowerShell

The companion PowerShell module keeps the same behavior behind thin compiled cmdlets:

```powershell
Send-VirusTotalMonitorFile `
    -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY `
    -File '.\TestimoX.CLI.exe' `
    -Path '/TestimoX/0.1.0/win-x64/TestimoX.CLI.exe' `
    -Details 'Signed TestimoX release artifact'

Get-VirusTotalMonitorItem -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY -List -Tag new-detections -All
Get-VirusTotalMonitorEvent -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY -Filter 'action:DETECTED' -All
Get-VirusTotalMonitorStatistics -ApiKey $env:VIRUSTOTAL_MONITOR_API_KEY
```

API keys are used only to create the client and are not included in upload results or request diagnostics.
