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
Get-VirusUser -ApiKey <string> -Id <string> [-Client <VirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Fetches public profile data for the specified username.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Get-VirusUser -ApiKey $ApiKey -Id 'user1'
```

Returns details for the given user identifier.

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
