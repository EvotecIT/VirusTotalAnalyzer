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
New-VirusVote -ResourceType <ResourceType> -Id <string> -Verdict <VoteVerdict> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
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
VirusTotal API key used when Client is not supplied. Defaults to the VIRUSTOTAL_API_KEY environment variable.

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
Possible values: Unknown, File, Url, IpAddress, Domain, Analysis, PrivateAnalysis, Comment, Vote, Relationship, Graph, SslCertificate, User, Group, Collection, ZipFile, LivehuntNotification, RetrohuntJob, IntelligenceHuntingRuleset, FileBehaviour

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
