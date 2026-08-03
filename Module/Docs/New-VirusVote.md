---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# New-VirusVote
## SYNOPSIS
Casts a vote for a resource.

## SYNTAX
### __AllParameterSets
```powershell
New-VirusVote -ApiKey <string> -ResourceType <ResourceType> -Id <string> -Verdict <VoteVerdict> [-Client <VirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Submits a harmless or malicious verdict for the specified resource.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-VirusVote -ApiKey $ApiKey -ResourceType File -Id 'abc' -Verdict Malicious
```

Marks the file identified by the given hash as malicious.

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

### -ResourceType
Resource type to vote on.

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

### -Verdict
Verdict to cast.

```yaml
Type: VoteVerdict
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Harmless, Malicious

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
