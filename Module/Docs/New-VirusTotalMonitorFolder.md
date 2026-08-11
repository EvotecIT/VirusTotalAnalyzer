---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# New-VirusTotalMonitorFolder
## SYNOPSIS
Creates a folder in VirusTotal Monitor.

## SYNTAX
### __AllParameterSets
```powershell
New-VirusTotalMonitorFolder [-Path] <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Creates a folder in VirusTotal Monitor.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-VirusTotalMonitorFolder -ApiKey $ApiKey -Path '/Product/1.0/'
```


## PARAMETERS

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

### -Path
Absolute Monitor folder path, including the trailing slash.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `VirusTotalAnalyzer.Models.MonitorItem`

## RELATED LINKS

- None
