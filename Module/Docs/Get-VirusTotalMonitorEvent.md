---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Get-VirusTotalMonitorEvent
## SYNOPSIS
Gets historical VirusTotal Monitor events.

## SYNTAX
### __AllParameterSets
```powershell
Get-VirusTotalMonitorEvent [-Filter <string>] [-Cursor <string>] [-JobId <string>] [-All] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Gets historical VirusTotal Monitor events.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> $page = Get-VirusTotalMonitorEvent -ApiKey $ApiKey; $next = Get-VirusTotalMonitorEvent -ApiKey $ApiKey -Cursor $page.Meta.Cursor -JobId $page.Meta.JobId
```

The default mode returns the full page so both cursor and job identifier remain available.

### EXAMPLE 2
```powershell
PS> Get-VirusTotalMonitorEvent -ApiKey $ApiKey -All
```


## PARAMETERS

### -All
Reads every page until VirusTotal returns no cursor.

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ApiKey
VirusTotal API key used when Client is not supplied.

```yaml
Type: String
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Cursor
Cursor at which to begin reading events.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Filter
Optional VirusTotal Monitor filter expression.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -JobId
Event job identifier returned by a previous page.

```yaml
Type: String
Parameter Sets: __AllParameterSets
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

- `None`

## OUTPUTS

- `VirusTotalAnalyzer.Models.MonitorEvent`
- `VirusTotalAnalyzer.Models.PagedResponse[VirusTotalAnalyzer.Models.MonitorEvent]`

## RELATED LINKS

- None
