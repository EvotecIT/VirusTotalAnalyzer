---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Get-VirusUser
## SYNOPSIS
Retrieves information about a VirusTotal user.

## SYNTAX
### __AllParameterSets
```powershell
Get-VirusUser -Id <string> [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Fetches the documented user object. Quotas and privileges are populated when visible to the caller.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Get-VirusUser -ApiKey $ApiKey -Id 'user1'
```

Returns details for the given user identifier.

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
Identifier of the user to retrieve.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`

## OUTPUTS

- `None`

## RELATED LINKS

- None
