---
external help file: VirusTotalAnalyzer-help.xml
Module Name: VirusTotalAnalyzer
online version: https://github.com/EvotecIT/VirusTotalAnalyzer
schema: 2.0.0
---
# Get-VirusRelationship
## SYNOPSIS
Retrieves useful typed relationships for VirusTotal network objects.

## SYNTAX
### Domain (Default)
```powershell
Get-VirusRelationship -DomainName <string> -Relationship <VirusTotalRelationshipType> [-Limit <Int32>] [-Cursor <string>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

### IPAddress
```powershell
Get-VirusRelationship -IPAddress <string> -Relationship <VirusTotalRelationshipType> [-Limit <Int32>] [-Cursor <string>] [-ApiKey <string>] [-Client <IVirusTotalClient>] [<CommonParameters>]
```

## DESCRIPTION
Returns typed historical WHOIS, DNS, resolution, certificate, and related-file objects instead of generic relationship descriptors.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Get-VirusRelationship -DomainName 'example.com' -Relationship HistoricalWhois
```


### EXAMPLE 2
```powershell
PS> Get-VirusRelationship -IPAddress '1.1.1.1' -Relationship CommunicatingFiles -Limit 10
```


## PARAMETERS

### -ApiKey
VirusTotal API key used when Client is not supplied. Defaults to the VIRUSTOTAL_API_KEY environment variable.

```yaml
Type: String
Parameter Sets: Domain, IPAddress
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
Parameter Sets: Domain, IPAddress
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Cursor
Cursor returned by a previous relationship request.

```yaml
Type: String
Parameter Sets: Domain, IPAddress
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain whose relationships should be retrieved.

```yaml
Type: String
Parameter Sets: Domain
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -IPAddress
IP address whose relationships should be retrieved.

```yaml
Type: String
Parameter Sets: IPAddress
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -Limit
Maximum number of relationship objects to request.

```yaml
Type: Int32
Parameter Sets: Domain, IPAddress
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Relationship
Typed relationship to retrieve.

```yaml
Type: VirusTotalRelationshipType
Parameter Sets: Domain, IPAddress
Aliases: None
Possible values: HistoricalWhois, Resolutions, HistoricalSslCertificates, CommunicatingFiles, ReferrerFiles

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

- `VirusTotalAnalyzer.Models.WhoisRecord`
- `VirusTotalAnalyzer.Models.Resolution`
- `VirusTotalAnalyzer.Models.SslCertificate`
- `VirusTotalAnalyzer.Models.FileReport`

## RELATED LINKS

- [https://docs.virustotal.com/reference/domain-object-historical-whois](https://docs.virustotal.com/reference/domain-object-historical-whois)
