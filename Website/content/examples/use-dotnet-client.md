---
title: "Use the .NET client"
description: "Use VirusTotalAnalyzer from C# with an environment-provided API key."
layout: docs
---

This pattern is useful when VirusTotal lookups are part of an application or automation service.

It is adapted from `VirusTotalAnalyzer.Examples/GetFileReportExample.cs`.

## Example

```csharp
using VirusTotalAnalyzer;

var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
using IVirusTotalClient client = VirusTotalClient.Create(apiKey);

var report = await client.GetFileReportAsync("44d88612fea8a8f36de82e1278abb02f");

Console.WriteLine(report?.Id);
```

## What this demonstrates

- using the .NET client directly
- keeping the API key out of source
- starting with a known public test hash

## Source

- [GetFileReportExample.cs](https://github.com/EvotecIT/VirusTotalAnalyzer/blob/master/VirusTotalAnalyzer.Examples/GetFileReportExample.cs)

