---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Set-VirusTotalMonitorItem
## SYNOPSIS
Sets publisher details on a VirusTotal Monitor item.

## SYNTAX
### __AllParameterSets
```powershell
Set-VirusTotalMonitorItem [-Id] <string> -Details <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Sets publisher details on a VirusTotal Monitor item.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Set-VirusTotalMonitorItem -ApiKey $ApiKey -Id 'monitor-item-id' -Details 'Signed release build'
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

### -Details
Publisher details stored with the item.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Id
Identifier of the Monitor item to configure.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`

## OUTPUTS

- `VirusTotalAnalyzer.Models.MonitorItem`

## RELATED LINKS

- None
