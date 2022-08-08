function Get-VirusReport {
    <#
    .SYNOPSIS
    Get the report from Virus Total about file, hash, url, ip address or domain.

    .DESCRIPTION
    Get the report from Virus Total about file, hash, url, ip address or domain.

    .PARAMETER ApiKey
    Provide ApiKey from Virus Total.

    .PARAMETER FileHash
    Provide FileHash to check. You can do this with Get-FileHash.

    .PARAMETER File
    Provide FilePath to a file to check.

    .PARAMETER Url
    Provide Url to check on Virus Total

    .PARAMETER IPAddress
    Provide IPAddress to check on Virus Total

    .PARAMETER DomainName
    Provide DomainName to check on Virus Total

    .PARAMETER Search
    Search for file hash, URL, domain, IP address or Tag comments.

    .EXAMPLE
    $VTApi = 'ApiKey from VirusTotal'

    Get-VirusReport -ApiKey $VTApi -FileHash 'BFF77EECBB2F7DA25ECBC9D9673E5DC1DB68DCC68FD76D006E836F9AC61C547E'
    Get-VirusReport -ApiKey $VTApi -File 'C:\Support\GitHub\PSPublishModule\Releases\v0.9.47\PSPublishModule.psm1'
    Get-VirusReport -ApiKey $VTApi -DomainName 'evotec.xyz'
    Get-VirusReport -ApiKey $VTApi -IPAddress '1.1.1.1'

    .NOTES
    General notes
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory)][string] $ApiKey,
        [Parameter(ParameterSetName = "FileHash", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $FileHash,
        [Parameter(ParameterSetName = "FileInformation", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [System.IO.FileInfo] $File,
        [alias('Uri')][Parameter(ParameterSetName = "Url", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Uri] $Url,
        [Parameter(ParameterSetName = "IPAddress", ValueFromPipeline , ValueFromPipelineByPropertyName)]
        [string] $IPAddress,
        [Parameter(ParameterSetName = "DomainName", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $DomainName,
        [Parameter(ParameterSetName = "Search", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $Search
    )
    Process {
        $RestMethod = @{}
        if ($PSCmdlet.ParameterSetName -eq 'FileInformation') {
            $VTFileHash = Get-FileHash -LiteralPath $File -Algorithm SHA256
            $RestMethod = @{
                Method  = 'GET'
                Uri     = "https://www.virustotal.com/api/v3/files/$($VTFileHash.Hash)"
                Headers = @{
                    "Accept"   = "application/json"
                    'X-Apikey' = $ApiKey
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "FileHash") {
            $VTFileHash = $FileHash
            $RestMethod = @{
                Method  = 'GET'
                Uri     = "https://www.virustotal.com/api/v3/files/$FileHash"
                Headers = @{
                    "Accept"   = "application/json"
                    'X-Apikey' = $ApiKey
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "Url") {
            $RestMethod = @{
                Method  = 'POST'
                Uri     = "https://www.virustotal.com/api/v3/urls/$Url"
                Headers = @{
                    "Accept"   = "application/json"
                    'X-Apikey' = $ApiKey
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "IPAddress") {
            $RestMethod = @{
                Method  = 'GET'
                Uri     = "http://www.virustotal.com/api/v3/ip_addresses/$IPAddress"
                Headers = @{
                    "Accept"   = "application/json"
                    'X-Apikey' = $ApiKey
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "DomainName") {
            $RestMethod = @{
                Method  = 'GET'
                Uri     = "http://www.virustotal.com/api/v3/domains/$DomainName"
                Headers = @{
                    "Accept"   = "application/json"
                    'X-Apikey' = $ApiKey
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'Search') {
            #$SearchQueryEscaped = [System.Web.HttpUtility]::UrlEncode(($Search)
            #$SearchQueryEscaped = [uri]::EscapeDataString($Search)
            $SearchQueryEscaped = [uri]::EscapeUriString($Search)
            $RestMethod = @{
                Method  = 'GET'
                Uri     = "http://www.virustotal.com/api/v3/search?query=$SearchQueryEscaped"
                Headers = @{
                    "Accept"   = "application/json"
                    'X-Apikey' = $ApiKey
                }
            }
        }
        $InvokeApiOutput = Invoke-RestMethod @RestMethod -ErrorAction Stop
        $InvokeApiOutput
    }
}

