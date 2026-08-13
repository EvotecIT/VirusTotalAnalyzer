# VirusTotalAnalyzer - VirusTotal API v3 client for .NET + PowerShell

📦 PowerShell Gallery

[![powershell gallery](https://img.shields.io/powershellgallery/v/VirusTotalAnalyzer.svg)](https://www.powershellgallery.com/packages/VirusTotalAnalyzer)
[![powershell gallery preview](https://img.shields.io/powershellgallery/vpre/VirusTotalAnalyzer.svg?label=powershell%20gallery%20preview&colorB=yellow)](https://www.powershellgallery.com/packages/VirusTotalAnalyzer)
[![powershell gallery downloads](https://img.shields.io/powershellgallery/dt/VirusTotalAnalyzer.svg)](https://www.powershellgallery.com/packages/VirusTotalAnalyzer)

📦 NuGet Package

[![nuget downloads](https://img.shields.io/nuget/dt/VirusTotalAnalyzer?label=nuget%20downloads)](https://www.nuget.org/packages/VirusTotalAnalyzer)
[![nuget version](https://img.shields.io/nuget/v/VirusTotalAnalyzer)](https://www.nuget.org/packages/VirusTotalAnalyzer)

🛠️ Project Information

[![build](https://github.com/EvotecIT/VirusTotalAnalyzer/actions/workflows/test.yml/badge.svg)](https://github.com/EvotecIT/VirusTotalAnalyzer/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/EvotecIT/VirusTotalAnalyzer/branch/master/graph/badge.svg)](https://codecov.io/gh/EvotecIT/VirusTotalAnalyzer)
[![top language](https://img.shields.io/github/languages/top/EvotecIT/VirusTotalAnalyzer.svg)](https://github.com/EvotecIT/VirusTotalAnalyzer)
[![license](https://img.shields.io/github/license/EvotecIT/VirusTotalAnalyzer.svg)](https://github.com/EvotecIT/VirusTotalAnalyzer)

👨‍💻 Author & Social

[![Twitter follow](https://img.shields.io/twitter/follow/PrzemyslawKlys.svg?label=Twitter%20%40PrzemyslawKlys&style=social)](https://twitter.com/PrzemyslawKlys)
[![Blog](https://img.shields.io/badge/Blog-evotec.xyz-2A6496.svg)](https://evotec.xyz/hub)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-pklys-0077B5.svg?logo=LinkedIn)](https://www.linkedin.com/in/pklys)
[![Threads](https://img.shields.io/badge/Threads-@PrzemyslawKlys-000000.svg?logo=Threads&logoColor=White)](https://www.threads.net/@przemyslaw.klys)
[![Discord](https://img.shields.io/discord/508328927853281280?style=flat-square&label=discord%20chat)](https://evo.yt/discord)

## What it's all about

**VirusTotalAnalyzer** is a .NET + PowerShell wrapper around the VirusTotal API v3. It provides a modern .NET client and a small set of PowerShell cmdlets for common workflows such as looking up files, URLs, domains, IPs, and submitting content for analysis.

## Highlights

- .NET client with async APIs, pagination helpers, and typed models
- PowerShell module for quick lookups and submissions
- Cross-platform CI (Windows, Linux, macOS) and PowerShell 5.1 coverage
- Examples for files, URLs, graphs, comments, votes, and more

## First 60 seconds

### PowerShell

```powershell
$env:VT_API_KEY = 'YOUR_API_KEY'
Import-Module VirusTotalAnalyzer -Force
Get-VirusReport -ApiKey $env:VT_API_KEY -Hash '44d88612fea8a8f36de82e1278abb02f'
```

### C#

```csharp
using System;
using VirusTotalAnalyzer;

IVirusTotalClient client = VirusTotalClient.Create(Environment.GetEnvironmentVariable("VT_API_KEY"));
var report = await client.GetFileReportAsync("44d88612fea8a8f36de82e1278abb02f");
Console.WriteLine(report?.Id);
```

## Supported targets

### .NET library

| Target | Notes |
| --- | --- |
| .NET Framework 4.7.2 | Windows PowerShell 5.1 compatibility |
| .NET 8 | Cross-platform |
| .NET 9 | Cross-platform |

### PowerShell

| Edition | Platform | Notes |
| --- | --- | --- |
| Windows PowerShell 5.1 | Windows | Uses `net472` build |
| PowerShell 7+ | Windows, Linux, macOS | Uses modern .NET builds |

## Installation

### PowerShell

```powershell
Install-Module -Name VirusTotalAnalyzer -Scope CurrentUser
```

### .NET (library)

```powershell
dotnet add package VirusTotalAnalyzer
```

Reference the `VirusTotalAnalyzer` project directly, or use the built DLL from the module artifacts/release package.

## API key setup

You need a VirusTotal API key. Create an account, then open your profile in the VirusTotal web UI and copy the API key.
Direct link: [My API key](https://www.virustotal.com/gui/my-apikey)

Recommended: store it in an environment variable so it doesn't end up in scripts or logs.

### PowerShell

```powershell
$env:VT_API_KEY = 'YOUR_API_KEY'
```

### C#

```csharp
var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
```

## Hello world

### PowerShell

```powershell
Import-Module VirusTotalAnalyzer -Force
Get-VirusReport -ApiKey $env:VT_API_KEY -Hash '44d88612fea8a8f36de82e1278abb02f'
```

### C#

```csharp
using System;
using VirusTotalAnalyzer;

IVirusTotalClient client = VirusTotalClient.Create(Environment.GetEnvironmentVariable("VT_API_KEY"));
var report = await client.GetFileReportAsync("44d88612fea8a8f36de82e1278abb02f");
Console.WriteLine(report?.Id);
```

## Quick usage (PowerShell)

```powershell
Import-Module VirusTotalAnalyzer -Force

$apiKey = 'APIKEY'

# File / hash / URL / domain / IP
Get-VirusReport -ApiKey $apiKey -Hash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
Get-VirusReport -ApiKey $apiKey -File "C:\Samples\TestFile.txt"
Get-VirusReport -ApiKey $apiKey -Search "https://evotec.xyz"
Get-VirusReport -ApiKey $apiKey -DomainName 'evotec.xyz'
Get-VirusReport -ApiKey $apiKey -IPAddress '1.1.1.1'
```

```powershell
Import-Module VirusTotalAnalyzer -Force

$apiKey = 'APIKEY'

# Submit URL or file for scanning
New-VirusScan -ApiKey $apiKey -Url 'https://evotec.pl'
New-VirusScan -ApiKey $apiKey -File "C:\Samples\TestFile.txt"
```

## Quick usage (C#)

```csharp
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");

try {
    var report = await client.GetFileReportAsync(
        "44d88612fea8a8f36de82e1278abb02f",
        fields: new[] { "md5", "sha256" },
        relationships: new[] { "analyses" });

    Console.WriteLine(report?.Id);
    Console.WriteLine(report?.Attributes.CreationDate);
}
catch (RateLimitExceededException ex) {
    Console.WriteLine($"Rate limit exceeded. Retry after: {ex.RetryAfter}");
}
catch (ApiException ex) {
    Console.WriteLine($"API error: {ex.Error?.Message}");
}
```

## Cmdlets

| Cmdlet | Description |
| --- | --- |
| `Get-VirusReport` | Retrieve file, URL, domain, IP, or analysis reports |
| `New-VirusScan` | Submit a file or URL for analysis or re-analysis |
| `Get-VirusComment` | Retrieve comments for a file or URL |
| `New-VirusVote` | Vote on a file or URL |
| `Get-VirusUser` | Get account and quota information |

## Examples

- .NET samples: `VirusTotalAnalyzer.Examples`
- PowerShell samples: `Module/Examples`
- Blog post: [Working with VirusTotal from PowerShell](https://evotec.xyz/working-with-virustotal-from-powershell/)

## API coverage & roadmap

- Coverage matrix and parity plan: [Docs/API-Coverage.md](Docs/API-Coverage.md)

## Build and test

```powershell
dotnet restore VirusTotalAnalyzer.sln
dotnet build VirusTotalAnalyzer.sln -c Release
dotnet test VirusTotalAnalyzer.Tests/VirusTotalAnalyzer.Tests.csproj -c Release
```

```powershell
pwsh -NoLogo -NoProfile -Command "Invoke-Pester -Path 'Module/Tests' -Output Detailed -CI"
```

```powershell
powershell -NoLogo -NoProfile -Command "Invoke-Pester -Path 'Module/Tests' -Output Detailed -CI"
```

## License

MIT.
