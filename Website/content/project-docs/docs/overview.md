---
title: "VirusTotalAnalyzer Overview"
description: "How VirusTotalAnalyzer fits VirusTotal API workflows."
layout: docs
---

VirusTotalAnalyzer is useful when VirusTotal lookups or submissions need to be scripted from PowerShell or embedded into a .NET workflow.

## Common fit

- look up a known hash, URL, domain, or IP address
- submit a URL or file for analysis
- build .NET tooling on top of typed VirusTotal API models
- keep PowerShell and application usage aligned around the same client library

## Good operating pattern

Start with lookups before submissions. Store the API key outside source control, and be careful with any file submission workflow because uploaded content may leave your environment.

