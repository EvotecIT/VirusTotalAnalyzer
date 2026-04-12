---
title: "Look up a known hash from PowerShell"
description: "Use VirusTotalAnalyzer to retrieve a file hash report."
layout: docs
---

This pattern is useful for validating the module and API key before using broader workflows.

It is adapted from `Module/Examples/Example-GetVirusTotalReport.ps1`.

## Example

```powershell
Import-Module VirusTotalAnalyzer

$apiKey = $env:VT_API_KEY
$eicarHash = '44d88612fea8a8f36de82e1278abb02f'

Get-VirusReport -ApiKey $apiKey -Hash $eicarHash
```

## What this demonstrates

- reading the API key from the environment
- querying a known public test hash
- avoiding private files and customer URLs in the first example

## Source

- [Example-GetVirusTotalReport.ps1](https://github.com/EvotecIT/VirusTotalAnalyzer/blob/master/Module/Examples/Example-GetVirusTotalReport.ps1)

