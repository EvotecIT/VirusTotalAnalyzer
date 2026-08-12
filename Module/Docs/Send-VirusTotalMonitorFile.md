---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Send-VirusTotalMonitorFile
## SYNOPSIS
Uploads a publisher file to VirusTotal Monitor.

## SYNTAX
### Path (Default)
```powershell
Send-VirusTotalMonitorFile [-File] <string> -Path <string> [-Details <string>] [-SkipHashVerification] [-VerificationTimeoutSeconds <int>] [-PollingIntervalSeconds <int>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ExistingItem
```powershell
Send-VirusTotalMonitorFile [-File] <string> -ExistingItemId <string> [-Details <string>] [-SkipHashVerification] [-VerificationTimeoutSeconds <int>] [-PollingIntervalSeconds <int>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Uploads a publisher file to VirusTotal Monitor.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Send-VirusTotalMonitorFile -ApiKey $ApiKey -File 'C:\releases\app.exe' -Path '/Product/1.0/app.exe'
```


### EXAMPLE 2
```powershell
PS> Send-VirusTotalMonitorFile -ApiKey $ApiKey -File 'C:\releases\app.exe' -ExistingItemId 'monitor-item-id'
```


## PARAMETERS

### -ApiKey
VirusTotal API key used when Client is not supplied. Defaults to the VIRUSTOTAL_API_KEY environment variable.

```yaml
Type: String
Parameter Sets: Path, ExistingItem
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
Parameter Sets: Path, ExistingItem
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Details
Optional publisher details assigned after upload.

```yaml
Type: String
Parameter Sets: Path, ExistingItem
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExistingItemId
Existing Monitor item identifier whose contents will be replaced.

```yaml
Type: String
Parameter Sets: ExistingItem
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -File
Local file to upload.

```yaml
Type: String
Parameter Sets: Path, ExistingItem
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Path
Absolute destination path in Monitor.

```yaml
Type: String
Parameter Sets: Path
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollingIntervalSeconds
Seconds between Monitor item verification requests.

```yaml
Type: Int32
Parameter Sets: Path, ExistingItem
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipHashVerification
Returns after upload without polling for the remote SHA-256.

```yaml
Type: SwitchParameter
Parameter Sets: Path, ExistingItem
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VerificationTimeoutSeconds
Maximum seconds to wait for a remote SHA-256.

```yaml
Type: Int32
Parameter Sets: Path, ExistingItem
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

## OUTPUTS

- `VirusTotalAnalyzer.Models.MonitorUploadResult`

## RELATED LINKS

- None
