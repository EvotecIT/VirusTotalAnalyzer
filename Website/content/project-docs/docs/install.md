---
title: "Install VirusTotalAnalyzer"
description: "Install VirusTotalAnalyzer for PowerShell or .NET."
layout: docs
---

Install the PowerShell module:

```powershell
Install-Module -Name VirusTotalAnalyzer -Scope CurrentUser
Import-Module VirusTotalAnalyzer
```

Use the .NET library from NuGet:

```powershell
dotnet add package VirusTotalAnalyzer
```

Keep the API key in an environment variable or your normal secret store:

```powershell
$env:VT_API_KEY = '<virus-total-api-key>'
```

