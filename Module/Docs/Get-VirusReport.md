---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Get-VirusReport
## SYNOPSIS
Retrieves analysis reports from VirusTotal.

## SYNTAX
### FileInformation (Default)
```powershell
Get-VirusReport -File <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### Analysis
```powershell
Get-VirusReport -AnalysisId <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### Hash
```powershell
Get-VirusReport -Hash <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### Url
```powershell
Get-VirusReport -Url <uri> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### IPAddress
```powershell
Get-VirusReport -IPAddress <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### DomainName
```powershell
Get-VirusReport -DomainName <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### Search
```powershell
Get-VirusReport -Search <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Queries the VirusTotal API for information about files, hashes, URLs, IP addresses, domains, or existing analyses.

Provide an API key or an existing IVirusTotalClient to authenticate requests.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Get-VirusReport -ApiKey $ApiKey -File 'C:\\samples\\app.exe'
```

Calculates the file hash and returns the latest analysis.

### EXAMPLE 2
```powershell
PS> Get-VirusReport -ApiKey $ApiKey -Url 'https://example.com'
```

Displays detection results for the provided URL.

## PARAMETERS

### -AnalysisId
Analysis identifier returned from a previous scan.

```yaml
Type: String
Parameter Sets: Analysis
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -ApiKey
VirusTotal API key used when Client is not supplied.

```yaml
Type: String
Parameter Sets: FileInformation, Analysis, Hash, Url, IPAddress, DomainName, Search
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Client
Existing client to reuse. The cmdlet never disposes caller-owned clients.

```yaml
Type: IVirusTotalClient
Parameter Sets: FileInformation, Analysis, Hash, Url, IPAddress, DomainName, Search
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain name to inspect.

```yaml
Type: String
Parameter Sets: DomainName
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -File
Path to a local file to compute its hash.

```yaml
Type: String
Parameter Sets: FileInformation
Aliases: FileHash
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Hash
SHA256 or other supported hash to look up.

```yaml
Type: String
Parameter Sets: Hash
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -IPAddress
IP address to inspect.

```yaml
Type: String
Parameter Sets: IPAddress
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Search
Free-form search expression.

```yaml
Type: String
Parameter Sets: Search
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Url
URL to check against VirusTotal.

```yaml
Type: Uri
Parameter Sets: Url
Aliases: Uri
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`
- `System.Uri`

## OUTPUTS

- `None`

## RELATED LINKS

- [https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [https://github.com/EvotecIT/VirusTotalAnalyzer](https://github.com/EvotecIT/VirusTotalAnalyzer)

## NOTES

### Note

Each request consumes your VirusTotal API quota.
