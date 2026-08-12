---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Get-VirusTotalMonitorItem
## SYNOPSIS
Gets one Monitor item or lists publisher Monitor items.

## SYNTAX
### ById (Default)
```powershell
Get-VirusTotalMonitorItem [-Id] <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### List
```powershell
Get-VirusTotalMonitorItem -List [-Filter <string>] [-Path <string>] [-ParentItemId <string>] [-Tag <string[]>] [-Limit <Int32>] [-Cursor <string>] [-All] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Gets one Monitor item or lists publisher Monitor items.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Get-VirusTotalMonitorItem -ApiKey $ApiKey -Id 'monitor-item-id'
```


### EXAMPLE 2
```powershell
PS> $page = Get-VirusTotalMonitorItem -ApiKey $ApiKey -List -Path '/releases/'
```

List mode returns the full page unless All is specified, preserving its continuation cursor.

## PARAMETERS

### -All
Reads every page until VirusTotal returns no cursor.

```yaml
Type: SwitchParameter
Parameter Sets: List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ApiKey
VirusTotal API key used when Client is not supplied. Defaults to the VIRUSTOTAL_API_KEY environment variable.

```yaml
Type: String
Parameter Sets: ById, List
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
Parameter Sets: ById, List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Cursor
Cursor at which to begin listing.

```yaml
Type: String
Parameter Sets: List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Filter
Optional VirusTotal Monitor item filter expression.

```yaml
Type: String
Parameter Sets: List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Id
Monitor item identifier.

```yaml
Type: String
Parameter Sets: ById
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Limit
Maximum number of items requested per page.

```yaml
Type: Int32
Parameter Sets: List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -List
Selects list mode instead of retrieving one item.

```yaml
Type: SwitchParameter
Parameter Sets: List
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ParentItemId
Lists children of this Monitor folder item.

```yaml
Type: String
Parameter Sets: List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
Lists items below this absolute Monitor path.

```yaml
Type: String
Parameter Sets: List
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tag
Lists items matching one or more Monitor tags.

```yaml
Type: String[]
Parameter Sets: List
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

- `VirusTotalAnalyzer.Models.MonitorItem`
- `VirusTotalAnalyzer.Models.PagedResponse[VirusTotalAnalyzer.Models.MonitorItem]`

## RELATED LINKS

- None
