function New-VirusScan {
    <#
    .SYNOPSIS
    Send a file, file hash or url to VirusTotal for a scan.

    .DESCRIPTION
    Send a file, file hash or url to VirusTotal for a scan using Virus Total v3 Api.
    If file hash is provided then we tell VirusTotal to reanalyze the file it has rather than sending a new file.

    .PARAMETER ApiKey
    ApiKey to use for the scan. This key is available only for registred users (free).

    .PARAMETER Hash
    Provide a file hash to scan on VirusTotal (file itself is not sent)

    .PARAMETER FileHash
    Porvide a file which hash will be used to send to Virus Total (file itself is not sent)

    .PARAMETER File
    Provide a file path for a file to sendto Virus Total.

    .PARAMETER Url
    Provide a URL to send to Virus Total.

    .PARAMETER Password
    Password to use for the file. This is used for password protected files.

    .EXAMPLE
    $VTApi = 'YourApiCode'

    New-VirusScan -ApiKey $VTApi -Url 'evotec.pl'
    New-VirusScan -ApiKey $VTApi -Url 'https://evotec.pl'

    .EXAMPLE
    $VTApi = 'YourApiCode

    # Submit file to scan
    $Output = New-VirusScan -ApiKey $VTApi -File "C:\Users\przemyslaw.klys\Documents\WindowsPowerShell\Modules\AuditPolicy\AuditPolicy.psd1"
    $Output | Format-List

    # Since the output will return scan ID we can use it to get the report
    $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
    $OutputScan | Format-List
    $OutputScan.Meta | Format-List
    $OutputScan.Data | Format-List

    .NOTES
    API Reference: https://developers.virustotal.com/reference/files-scan
    This function now supports large files (> 32MB) by requesting an upload_url.

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ApiKey,
        [Parameter(ParameterSetName = "Hash", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $Hash,
        [Parameter(ParameterSetName = "FileHash", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $FileHash,
        [Parameter(ParameterSetName = "FileInformation", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [System.IO.FileInfo] $File,
        [alias('Uri')][Parameter(ParameterSetName = "Url", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Uri] $Url,
        [string] $Password
    )
    process {
        $RestMethod = @{}
        if ($PSCmdlet.ParameterSetName -eq 'FileInformation') {
            if ($File.Length -gt 33554432) {
                # Request large file upload URL
                $UploadUrlResponse = Invoke-RestMethod -Method 'GET' -Uri 'https://www.virustotal.com/api/v3/files/upload_url' -Headers @{
                    "Accept"   = "application/json"
                    'x-apikey' = $ApiKey
                }
                $Boundary = [Guid]::NewGuid().ToString().Replace('-', '')
                $RestMethod = @{
                    Method      = 'POST'
                    Uri         = $UploadUrlResponse.data
                    Headers     = @{
                        "accept"   = "application/json"
                        'x-apikey' = $ApiKey
                        'password' = $Password
                    }
                    Body        = ConvertTo-VTBody -File $File -Boundary $Boundary
                    ContentType = 'multipart/form-data; boundary=' + $Boundary
                }
                Remove-EmptyValue -Hashtable $RestMethod.Headers
            } else {
                $Boundary = [Guid]::NewGuid().ToString().Replace('-', '')
                $RestMethod = @{
                    Method      = 'POST'
                    Uri         = 'https://www.virustotal.com/api/v3/files'
                    Headers     = @{
                        "Accept"   = "application/json"
                        'x-apikey' = $ApiKey
                        'password' = $Password
                    }
                    Body        = ConvertTo-VTBody -File $File -Boundary $Boundary
                    ContentType = 'multipart/form-data; boundary=' + $boundary
                }
                Remove-EmptyValue -Hashtable $RestMethod.Headers
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "Hash") {
            $RestMethod = @{
                Method  = 'POST'
                Uri     = "https://www.virustotal.com/api/v3/files/$Hash/analyse"
                Headers = @{
                    "Accept"   = "application / json"
                    'X-Apikey' = $ApiKey
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "FileHash") {
            if (Test-Path -LiteralPath $FileHash) {
                $VTFileHash = Get-FileHash -LiteralPath $FileHash -Algorithm SHA256
                $RestMethod = @{
                    Method  = 'POST'
                    Uri     = "https://www.virustotal.com/api/v3/files/$($VTFileHash.Hash)/analyse"
                    Headers = @{
                        "Accept"   = "application/json"
                        'X-Apikey' = $ApiKey
                    }
                }
            } else {
                Write-Warning -Message "New-VirusScan - File $FileHash doesn't exists. Skipping..."
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "Url") {
            $RestMethod = @{
                Method  = 'POST'
                Uri     = 'https://www.virustotal.com/api/v3/urls'
                Headers = @{
                    "Accept"       = "application/json"
                    'X-Apikey'     = $ApiKey
                    "Content-Type" = "application/x-www-form-urlencoded"
                }
                Body    = @{ 'url' = [uri]::EscapeUriString($Url) }
            }
        }
        if ($RestMethod.Count -gt 0) {
            try {
                $InvokeApiOutput = Invoke-RestMethod @RestMethod -ErrorAction Stop
                $InvokeApiOutput
            } catch {
                if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                    throw
                } else {
                    Write-Warning -Message "New-VirusScan - Using $($PSCmdlet.ParameterSetName) task failed with error: $($_.Exception.Message)"
                }
            }
        }
    }
}