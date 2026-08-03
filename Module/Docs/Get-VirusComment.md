---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Get-VirusComment
## SYNOPSIS
Retrieves comments for a specified resource.

## SYNTAX
### __AllParameterSets
```powershell
Get-VirusComment -ApiKey <string> -ResourceType <ResourceType> -Id <string> [-Limit <Int32>] [-Cursor <string>] [-Client <VirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Fetches community comments associated with files, URLs, IP addresses or domains.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Get-VirusComment -ApiKey $ApiKey -ResourceType File -Id 'abc'
```

Displays community feedback for the file with the given hash.

## PARAMETERS

### -ApiKey
VirusTotal API key.

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

### -Client
Existing VirusTotal client to reuse.

```yaml
Type: VirusTotalClient
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
Pagination cursor.

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

### -Id
Identifier of the resource.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Limit
Maximum number of comments to return.

```yaml
Type: Int32
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResourceType
Resource type to retrieve comments for.

```yaml
Type: ResourceType
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: File, Url, IpAddress, Domain, Analysis, PrivateAnalysis, Comment, Vote, Relationship, Search, Feed, Graph, SslCertificate, User, Collection, Bundle, LivehuntNotification, RetrohuntJob, RetrohuntNotification, MonitorItem, MonitorEvent, IntelligenceHuntingRuleset, FileBehaviour

Required: True
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

- `None`

## RELATED LINKS

- None
