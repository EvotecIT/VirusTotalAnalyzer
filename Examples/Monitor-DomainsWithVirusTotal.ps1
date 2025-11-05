<#
.SYNOPSIS
    Monitors domains using VirusTotal and sends email alerts for blocked/malicious domains.

.DESCRIPTION
    This script checks a list of domains against VirusTotal's database to determine if they
    are flagged as malicious, suspicious, or blocked. If any domain exceeds the configured
    thresholds, an email alert is sent. Designed to run as a scheduled task.

.PARAMETER ConfigFile
    Path to the JSON configuration file containing settings. If not specified, looks for
    'DomainMonitorConfig.json' in the script directory.

.PARAMETER DomainsFile
    Path to a text file containing one domain per line. Overrides the DomainsFile in config.

.PARAMETER ApiKey
    VirusTotal API key. Overrides the ApiKey in the configuration file.

.PARAMETER SendTestEmail
    Sends a test email to verify email configuration without checking domains.

.EXAMPLE
    .\Monitor-DomainsWithVirusTotal.ps1
    Runs the script using default configuration file.

.EXAMPLE
    .\Monitor-DomainsWithVirusTotal.ps1 -ConfigFile "C:\Scripts\config.json"
    Runs the script with a specific configuration file.

.EXAMPLE
    .\Monitor-DomainsWithVirusTotal.ps1 -SendTestEmail
    Sends a test email to verify email settings.

.NOTES
    Author: VirusTotalAnalyzer
    Version: 1.0
    Requires: VirusTotalAnalyzer PowerShell module

    Install module: Install-Module VirusTotalAnalyzer -Force

    API documentation: https://docs.virustotal.com/reference/domain-info
    Module documentation: https://evotec.xyz/working-with-virustotal-from-powershell/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile,

    [Parameter(Mandatory = $false)]
    [string]$DomainsFile,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [switch]$SendTestEmail
)

#Requires -Modules VirusTotalAnalyzer

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to console and optionally to a log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',

        [Parameter(Mandatory = $false)]
        [string]$LogFile
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
    }

    # File output
    if ($LogFile) {
        try {
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}

function Get-Configuration {
    <#
    .SYNOPSIS
        Loads configuration from JSON file with validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        throw "Configuration file not found: $Path"
    }

    try {
        $config = Get-Content -Path $Path -Raw | ConvertFrom-Json

        # Validate required properties
        $requiredProps = @('ApiKey', 'DomainsFile', 'EmailSettings', 'Thresholds')
        foreach ($prop in $requiredProps) {
            if (-not $config.PSObject.Properties[$prop]) {
                throw "Missing required configuration property: $prop"
            }
        }

        return $config
    }
    catch {
        throw "Failed to load configuration: $_"
    }
}

function Get-DomainList {
    <#
    .SYNOPSIS
        Reads domains from a text file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        throw "Domains file not found: $Path"
    }

    $domains = Get-Content -Path $Path | Where-Object {
        $_ -match '\S' -and $_ -notmatch '^\s*#'
    } | ForEach-Object { $_.Trim() }

    if ($domains.Count -eq 0) {
        throw "No domains found in file: $Path"
    }

    return $domains
}

function Test-DomainThreat {
    <#
    .SYNOPSIS
        Analyzes VirusTotal domain report and determines if it's a threat.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Report,

        [Parameter(Mandatory = $true)]
        $Thresholds
    )

    $attributes = $Report.Data.Attributes
    $stats = $attributes.LastAnalysisStats

    $isThreat = $false
    $reasons = @()

    # Check malicious detections
    if ($null -ne $stats.Malicious -and $stats.Malicious -gt $Thresholds.MaliciousCount) {
        $isThreat = $true
        $reasons += "Malicious detections: $($stats.Malicious)"
    }

    # Check suspicious detections
    if ($null -ne $stats.Suspicious -and $stats.Suspicious -gt $Thresholds.SuspiciousCount) {
        $isThreat = $true
        $reasons += "Suspicious detections: $($stats.Suspicious)"
    }

    # Check reputation score (negative is bad)
    if ($null -ne $attributes.Reputation -and $attributes.Reputation -lt $Thresholds.MinReputation) {
        $isThreat = $true
        $reasons += "Low reputation score: $($attributes.Reputation)"
    }

    # Check categories for malicious classifications
    if ($attributes.Categories) {
        $maliciousCategories = @('malware', 'phishing', 'malicious', 'spam', 'suspicious')
        $foundCategories = $attributes.Categories.PSObject.Properties |
            Where-Object { $maliciousCategories -contains $_.Value.ToLower() }

        if ($foundCategories) {
            $isThreat = $true
            $categories = ($foundCategories | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ', '
            $reasons += "Malicious categories: $categories"
        }
    }

    return @{
        IsThreat = $isThreat
        Reasons = $reasons
        Stats = $stats
        Reputation = $attributes.Reputation
        Categories = $attributes.Categories
        LastAnalysisDate = $attributes.LastAnalysisDate
    }
}

function Send-ThreatAlert {
    <#
    .SYNOPSIS
        Sends an email alert about detected threats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ThreatenedDomains,

        [Parameter(Mandatory = $true)]
        $EmailSettings,

        [Parameter(Mandatory = $false)]
        [switch]$IsTest
    )

    $subject = if ($IsTest) {
        "TEST - VirusTotal Domain Monitor"
    }
    else {
        "ALERT - Blocked Domains Detected ($($ThreatenedDomains.Count) domains)"
    }

    # Build HTML email body
    $htmlBody = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #d32f2f; }
        h2 { color: #1976d2; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; }
        td { border: 1px solid #ddd; padding: 12px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { color: #f57c00; }
        .danger { color: #d32f2f; }
        .info { color: #1976d2; }
        .footer { margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
"@

    if ($IsTest) {
        $htmlBody += @"
    <h1>Test Email - VirusTotal Domain Monitor</h1>
    <p>This is a test email to verify your email configuration is working correctly.</p>
    <p>Email sent at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p>If you received this email, your configuration is correct.</p>
"@
    }
    else {
        $htmlBody += @"
    <h1>Domain Threat Alert</h1>
    <p>The following domains have been flagged as potentially blocked or malicious by VirusTotal:</p>
    <p><strong>Scan Time:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p><strong>Total Threats Detected:</strong> $($ThreatenedDomains.Count)</p>

    <h2>Detected Threats</h2>
    <table>
        <tr>
            <th>Domain</th>
            <th>Malicious</th>
            <th>Suspicious</th>
            <th>Reputation</th>
            <th>Reasons</th>
        </tr>
"@

        foreach ($threat in $ThreatenedDomains) {
            $maliciousClass = if ($threat.Analysis.Stats.Malicious -gt 5) { 'danger' } else { 'warning' }
            $reputationClass = if ($threat.Analysis.Reputation -lt -50) { 'danger' } elseif ($threat.Analysis.Reputation -lt 0) { 'warning' } else { 'info' }

            $htmlBody += @"
        <tr>
            <td><strong>$($threat.Domain)</strong></td>
            <td class="$maliciousClass">$($threat.Analysis.Stats.Malicious)</td>
            <td class="warning">$($threat.Analysis.Stats.Suspicious)</td>
            <td class="$reputationClass">$($threat.Analysis.Reputation)</td>
            <td>$($threat.Analysis.Reasons -join '<br>')</td>
        </tr>
"@
        }

        $htmlBody += @"
    </table>

    <div class="footer">
        <p>This is an automated alert from the VirusTotal Domain Monitor.</p>
        <p>Please review these domains and take appropriate action.</p>
    </div>
"@
    }

    $htmlBody += @"
</body>
</html>
"@

    # Prepare email parameters
    $mailParams = @{
        From       = $EmailSettings.From
        To         = $EmailSettings.To
        Subject    = $subject
        Body       = $htmlBody
        BodyAsHtml = $true
        SmtpServer = $EmailSettings.SmtpServer
        Port       = $EmailSettings.Port
    }

    # Add CC if specified
    if ($EmailSettings.Cc) {
        $mailParams['Cc'] = $EmailSettings.Cc
    }

    # Add authentication if specified
    if ($EmailSettings.Username -and $EmailSettings.Password) {
        $securePassword = ConvertTo-SecureString $EmailSettings.Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($EmailSettings.Username, $securePassword)
        $mailParams['Credential'] = $credential
    }

    # Add SSL if specified
    if ($EmailSettings.UseSsl) {
        $mailParams['UseSsl'] = $true
    }

    try {
        Send-MailMessage @mailParams
        return $true
    }
    catch {
        throw "Failed to send email: $_"
    }
}

#endregion

#region Main Script

try {
    Write-Host "`n=== VirusTotal Domain Monitor ===" -ForegroundColor Cyan
    Write-Host "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Cyan

    # Determine config file path
    if (-not $ConfigFile) {
        $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath 'DomainMonitorConfig.json'
    }

    # Load configuration
    Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor Gray
    $config = Get-Configuration -Path $ConfigFile

    # Override config with parameters if provided
    if ($ApiKey) {
        $config.ApiKey = $ApiKey
    }

    if ($DomainsFile) {
        $config.DomainsFile = $DomainsFile
    }

    # Setup logging
    $logFile = if ($config.LogFile) {
        # Support relative paths
        if ([System.IO.Path]::IsPathRooted($config.LogFile)) {
            $config.LogFile
        }
        else {
            Join-Path -Path $PSScriptRoot -ChildPath $config.LogFile
        }
    }
    else {
        $null
    }

    Write-Log -Message "Script started" -Level Info -LogFile $logFile

    # Handle test email
    if ($SendTestEmail) {
        Write-Log -Message "Sending test email..." -Level Info -LogFile $logFile
        Send-ThreatAlert -ThreatenedDomains @() -EmailSettings $config.EmailSettings -IsTest
        Write-Log -Message "Test email sent successfully" -Level Success -LogFile $logFile
        exit 0
    }

    # Validate API key
    if (-not $config.ApiKey -or $config.ApiKey -eq 'YOUR_VIRUSTOTAL_API_KEY_HERE') {
        throw "Please configure a valid VirusTotal API key in the configuration file"
    }

    # Load domains
    $domainsPath = if ([System.IO.Path]::IsPathRooted($config.DomainsFile)) {
        $config.DomainsFile
    }
    else {
        Join-Path -Path $PSScriptRoot -ChildPath $config.DomainsFile
    }

    Write-Log -Message "Loading domains from: $domainsPath" -Level Info -LogFile $logFile
    $domains = Get-DomainList -Path $domainsPath
    Write-Log -Message "Found $($domains.Count) domains to check" -Level Info -LogFile $logFile

    # Check domains
    $threatenedDomains = @()
    $checkedCount = 0
    $errorCount = 0

    foreach ($domain in $domains) {
        $checkedCount++
        Write-Log -Message "[$checkedCount/$($domains.Count)] Checking domain: $domain" -Level Info -LogFile $logFile

        try {
            # Get domain report from VirusTotal
            $report = Get-VirusReport -ApiKey $config.ApiKey -DomainName $domain

            if ($report -and $report.Data) {
                # Analyze the report
                $analysis = Test-DomainThreat -Report $report -Thresholds $config.Thresholds

                if ($analysis.IsThreat) {
                    Write-Log -Message "THREAT DETECTED - $domain" -Level Warning -LogFile $logFile
                    $threatenedDomains += @{
                        Domain   = $domain
                        Analysis = $analysis
                    }
                }
                else {
                    Write-Log -Message "OK - $domain (Malicious: $($analysis.Stats.Malicious), Reputation: $($analysis.Reputation))" -Level Success -LogFile $logFile
                }
            }
            else {
                Write-Log -Message "No data returned for domain: $domain" -Level Warning -LogFile $logFile
            }

            # Rate limiting - respect API limits
            if ($checkedCount -lt $domains.Count) {
                Start-Sleep -Milliseconds $config.RateLimitDelayMs
            }
        }
        catch {
            $errorCount++
            Write-Log -Message "Error checking domain $domain : $_" -Level Error -LogFile $logFile

            # Continue with next domain unless too many errors
            if ($errorCount -gt 5) {
                throw "Too many errors encountered. Stopping execution."
            }
        }
    }

    # Send alert if threats detected
    if ($threatenedDomains.Count -gt 0) {
        Write-Log -Message "Sending alert email for $($threatenedDomains.Count) threatened domains" -Level Warning -LogFile $logFile

        try {
            Send-ThreatAlert -ThreatenedDomains $threatenedDomains -EmailSettings $config.EmailSettings
            Write-Log -Message "Alert email sent successfully" -Level Success -LogFile $logFile
        }
        catch {
            Write-Log -Message "Failed to send alert email: $_" -Level Error -LogFile $logFile
            throw
        }
    }
    else {
        Write-Log -Message "No threats detected. All domains are clean." -Level Success -LogFile $logFile
    }

    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total domains checked: $checkedCount" -ForegroundColor Gray
    Write-Host "Threats detected: $($threatenedDomains.Count)" -ForegroundColor $(if ($threatenedDomains.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Errors encountered: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host "Completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

    Write-Log -Message "Script completed successfully" -Level Success -LogFile $logFile

    # Exit with appropriate code
    exit $(if ($threatenedDomains.Count -gt 0) { 1 } else { 0 })
}
catch {
    $errorMessage = "Script failed: $_"
    Write-Log -Message $errorMessage -Level Error -LogFile $logFile
    Write-Host "`nERROR: $errorMessage" -ForegroundColor Red
    exit 2
}

#endregion
