---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# New-VirusScan
## SYNOPSIS
Submits resources to VirusTotal for scanning.

## SYNTAX
### Hash
```powershell
New-VirusScan -Hash <string> [-Password <string>] [-Wait] [-TimeoutSeconds <int>] [-PollingIntervalSeconds <int>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### FileHash
```powershell
New-VirusScan -FileHash <string> [-Password <string>] [-Wait] [-TimeoutSeconds <int>] [-PollingIntervalSeconds <int>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### FileInformation
```powershell
New-VirusScan -File <string> [-Password <string>] [-Wait] [-TimeoutSeconds <int>] [-PollingIntervalSeconds <int>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### Url
```powershell
New-VirusScan -Url <uri> [-Password <string>] [-Wait] [-TimeoutSeconds <int>] [-PollingIntervalSeconds <int>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Uploads files, hashes, or URLs to the VirusTotal API and returns the resulting analysis object.

You can rescan existing files by providing a known hash.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-VirusScan -ApiKey $ApiKey -File 'C:\\samples\\app.exe'
```

Starts a new analysis for the specified file.

### EXAMPLE 2
```powershell
PS> New-VirusScan -ApiKey $ApiKey -Url 'https://example.com'
```

Queues the URL for analysis and returns its identifier.

### EXAMPLE 3
```powershell
PS> $env:VIRUSTOTAL_API_KEY = 'your-api-key'; New-VirusScan -File 'C:\samples\app.exe' -Wait
```

Uses the environment API key and polls at a free-API-friendly interval.

## PARAMETERS

### -ApiKey
VirusTotal API key used when Client is not supplied. Defaults to the VIRUSTOTAL_API_KEY environment variable.

```yaml
Type: String
Parameter Sets: Hash, FileHash, FileInformation, Url
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
Parameter Sets: Hash, FileHash, FileInformation, Url
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -File
Path to a local file to upload for scanning.

```yaml
Type: String
Parameter Sets: FileInformation
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -FileHash
Path to a file whose hash should be recalculated and reanalysed.

```yaml
Type: String
Parameter Sets: FileHash
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Hash
Hash of an already submitted file to reanalyse.

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

### -Password
Password to use when submitting a protected archive.

```yaml
Type: String
Parameter Sets: Hash, FileHash, FileInformation, Url
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollingIntervalSeconds
Seconds between status requests. The default is suitable for the public API rate limit.

```yaml
Type: Int32
Parameter Sets: Hash, FileHash, FileInformation, Url
Aliases: None
Possible values:

Required: False
Position: named
Default value: 20
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeoutSeconds
Maximum number of seconds to wait for analysis completion.

```yaml
Type: Int32
Parameter Sets: Hash, FileHash, FileInformation, Url
Aliases: None
Possible values:

Required: False
Position: named
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### -Url
URL to submit for scanning.

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

### -Wait
Wait for VirusTotal to finish the submitted analysis.

```yaml
Type: SwitchParameter
Parameter Sets: Hash, FileHash, FileInformation, Url
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`
- `System.Uri`

## OUTPUTS

- `VirusTotalAnalyzer.Models.AnalysisReport`

## RELATED LINKS

- [https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-webrequest](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-webrequest)
- [https://github.com/EvotecIT/VirusTotalAnalyzer](https://github.com/EvotecIT/VirusTotalAnalyzer)

## NOTES

### Note

Submitted data is shared with the VirusTotal community.
