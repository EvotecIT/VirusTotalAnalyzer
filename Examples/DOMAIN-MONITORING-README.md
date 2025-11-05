# VirusTotal Domain Monitoring Script

A PowerShell script that monitors domains using VirusTotal's API and sends email alerts when domains are flagged as malicious, suspicious, or blocked. Designed for scheduled execution to provide continuous monitoring.

## Features

- **Automated Domain Checking**: Checks a list of domains against VirusTotal's threat intelligence database
- **Configurable Thresholds**: Customize detection sensitivity based on malicious counts, suspicious counts, and reputation scores
- **Email Alerts**: Sends HTML-formatted email alerts when threats are detected
- **Detailed Logging**: Comprehensive logging to both console and file
- **Rate Limiting**: Built-in API rate limiting to respect VirusTotal quota
- **Error Handling**: Robust error handling with graceful degradation
- **Scheduled Task Ready**: Designed to run as a Windows Task Scheduler job

## Prerequisites

### 1. Install VirusTotalAnalyzer Module

```powershell
Install-Module VirusTotalAnalyzer -Force -Verbose
```

### 2. Get VirusTotal API Key

1. Register for a free account at [VirusTotal](https://www.virustotal.com/)
2. Navigate to your [API key page](https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey)
3. Copy your API key

**Free Tier Limits**: 4 requests per minute, 500 requests per day

### 3. Configure SMTP Email Access

You'll need SMTP server details for sending alerts. Common providers:

- **Gmail**: `smtp.gmail.com:587` (requires [App Password](https://support.google.com/accounts/answer/185833))
- **Outlook/Office365**: `smtp.office365.com:587`
- **SendGrid**: `smtp.sendgrid.net:587`
- **Custom SMTP**: Your organization's mail server

## Installation

1. **Download the script files** to a directory (e.g., `C:\Scripts\DomainMonitor\`):
   - `Monitor-DomainsWithVirusTotal.ps1`
   - `DomainMonitorConfig.json`
   - `domains.txt`

2. **Configure the settings** in `DomainMonitorConfig.json`:

   ```json
   {
     "ApiKey": "your_virustotal_api_key_here",
     "DomainsFile": "domains.txt",
     "LogFile": "DomainMonitor.log",
     "RateLimitDelayMs": 15000,
     "Thresholds": {
       "MaliciousCount": 0,
       "SuspiciousCount": 3,
       "MinReputation": -10
     },
     "EmailSettings": {
       "From": "monitoring@yourcompany.com",
       "To": ["admin@yourcompany.com", "security@yourcompany.com"],
       "SmtpServer": "smtp.yourcompany.com",
       "Port": 587,
       "UseSsl": true,
       "Username": "monitoring@yourcompany.com",
       "Password": "your_email_password"
     }
   }
   ```

3. **Add domains to monitor** in `domains.txt`:

   ```text
   example.com
   mycompany.com
   partner-site.com
   ```

## Configuration Reference

### API Settings

| Setting | Description | Example |
|---------|-------------|---------|
| `ApiKey` | Your VirusTotal API key | `"abc123def456..."` |
| `DomainsFile` | Path to domains list file | `"domains.txt"` or `"C:\Data\domains.txt"` |
| `LogFile` | Path to log file (null to disable) | `"DomainMonitor.log"` |
| `RateLimitDelayMs` | Delay between requests (ms) | `15000` (15 seconds for free tier) |

### Threshold Settings

Controls when a domain triggers an alert:

| Threshold | Description | Recommended Value |
|-----------|-------------|-------------------|
| `MaliciousCount` | Max malicious detections before alert | `0` (alert on any malicious) |
| `SuspiciousCount` | Max suspicious detections before alert | `3` |
| `MinReputation` | Minimum acceptable reputation score | `-10` (alert if below -10) |

**Understanding VirusTotal Scores**:
- **Malicious**: Security vendors flagged the domain as malicious
- **Suspicious**: Security vendors flagged the domain as suspicious
- **Reputation**: Integer score (negative = bad, positive = good, range typically -100 to +100)
- **Categories**: Classification by security vendors (e.g., malware, phishing, spam)

### Email Settings

| Setting | Required | Description | Example |
|---------|----------|-------------|---------|
| `From` | Yes | Sender email address | `"alerts@company.com"` |
| `To` | Yes | Array of recipient emails | `["admin@company.com"]` |
| `Cc` | No | Array of CC recipients | `["manager@company.com"]` |
| `SmtpServer` | Yes | SMTP server hostname | `"smtp.gmail.com"` |
| `Port` | Yes | SMTP port | `587` or `465` or `25` |
| `UseSsl` | Yes | Use SSL/TLS encryption | `true` |
| `Username` | No* | SMTP authentication username | `"user@gmail.com"` |
| `Password` | No* | SMTP authentication password | `"app_password"` |

*Required if your SMTP server requires authentication

## Usage

### Manual Execution

Run the script manually to check domains:

```powershell
# Use default config file (DomainMonitorConfig.json in script directory)
.\Monitor-DomainsWithVirusTotal.ps1

# Use custom config file
.\Monitor-DomainsWithVirusTotal.ps1 -ConfigFile "C:\Config\custom-config.json"

# Override specific settings
.\Monitor-DomainsWithVirusTotal.ps1 -ApiKey "your_api_key" -DomainsFile "C:\Data\domains.txt"

# Send test email to verify configuration
.\Monitor-DomainsWithVirusTotal.ps1 -SendTestEmail
```

### Scheduled Execution

#### Option 1: Windows Task Scheduler (Recommended)

1. **Open Task Scheduler**: Press `Win + R`, type `taskschd.msc`, press Enter

2. **Create New Task**: Click "Create Task" in the Actions panel

3. **General Tab**:
   - Name: `VirusTotal Domain Monitor`
   - Description: `Monitors domains for threats using VirusTotal`
   - Security options: Select "Run whether user is logged on or not"
   - Check "Run with highest privileges"

4. **Triggers Tab**: Click "New"
   - Begin the task: `On a schedule`
   - Settings: `Daily`
   - Recur every: `1 days`
   - Repeat task every: `4 hours`
   - For a duration of: `Indefinitely`
   - Click OK

5. **Actions Tab**: Click "New"
   - Action: `Start a program`
   - Program/script: `powershell.exe`
   - Add arguments:
     ```
     -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\DomainMonitor\Monitor-DomainsWithVirusTotal.ps1"
     ```
   - Start in: `C:\Scripts\DomainMonitor\`
   - Click OK

6. **Conditions Tab**: Adjust as needed
   - Uncheck "Start the task only if the computer is on AC power" if running on laptop

7. **Settings Tab**:
   - Check "Allow task to be run on demand"
   - Check "Run task as soon as possible after a scheduled start is missed"
   - If the task fails, restart every: `10 minutes`

8. **Save**: Click OK and enter credentials when prompted

#### Option 2: PowerShell Scheduled Job

```powershell
$trigger = New-JobTrigger -Daily -At "9:00AM" -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration (New-TimeSpan -Days 1)

Register-ScheduledJob -Name "VirusTotalDomainMonitor" `
    -FilePath "C:\Scripts\DomainMonitor\Monitor-DomainsWithVirusTotal.ps1" `
    -Trigger $trigger

# View scheduled jobs
Get-ScheduledJob

# Remove scheduled job
Unregister-ScheduledJob -Name "VirusTotalDomainMonitor"
```

## Understanding Results

### Email Alert Format

When threats are detected, you'll receive an HTML email with:

- **Summary**: Total threats detected and scan time
- **Details Table**: For each threatened domain:
  - Domain name
  - Malicious detection count
  - Suspicious detection count
  - Reputation score
  - Specific reasons for flagging

### Exit Codes

The script returns different exit codes for automation:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success - No threats detected |
| `1` | Success - Threats detected (email sent) |
| `2` | Error - Script failed to execute |

### Log File

The log file contains detailed execution information:

```
[2025-11-05 10:00:00] [Info] Script started
[2025-11-05 10:00:01] [Info] Loading domains from: domains.txt
[2025-11-05 10:00:01] [Info] Found 3 domains to check
[2025-11-05 10:00:02] [Info] [1/3] Checking domain: google.com
[2025-11-05 10:00:03] [Success] OK - google.com (Malicious: 0, Reputation: 100)
[2025-11-05 10:00:18] [Info] [2/3] Checking domain: malicious-site.com
[2025-11-05 10:00:19] [Warning] THREAT DETECTED - malicious-site.com
[2025-11-05 10:00:34] [Info] [3/3] Checking domain: example.com
[2025-11-05 10:00:35] [Success] OK - example.com (Malicious: 0, Reputation: 50)
[2025-11-05 10:00:35] [Warning] Sending alert email for 1 threatened domains
[2025-11-05 10:00:36] [Success] Alert email sent successfully
[2025-11-05 10:00:36] [Success] Script completed successfully
```

## Best Practices

### 1. API Rate Limiting

**Free Tier**: 4 requests/minute (500/day)
- Set `RateLimitDelayMs` to `15000` (15 seconds between requests)
- Monitor up to 30 domains per run (7.5 minutes per execution)

**Premium Tier**: 1000 requests/minute
- Set `RateLimitDelayMs` to `100` (0.1 seconds between requests)
- Can monitor thousands of domains efficiently

### 2. Threshold Configuration

Start conservative and adjust based on false positives:

**High Security Environment**:
```json
{
  "MaliciousCount": 0,
  "SuspiciousCount": 1,
  "MinReputation": 0
}
```

**Balanced Approach** (Recommended):
```json
{
  "MaliciousCount": 0,
  "SuspiciousCount": 3,
  "MinReputation": -10
}
```

**Low False Positives**:
```json
{
  "MaliciousCount": 2,
  "SuspiciousCount": 5,
  "MinReputation": -50
}
```

### 3. Email Security

**Don't store plaintext passwords!** Consider these alternatives:

#### Option A: Use Windows Credential Manager

```powershell
# Store credential once
$cred = Get-Credential
$cred.Password | ConvertFrom-SecureString | Set-Content "C:\Scripts\encrypted-password.txt"

# Modify script to load encrypted password
$encryptedPassword = Get-Content "C:\Scripts\encrypted-password.txt" | ConvertTo-SecureString
```

#### Option B: Use Environment Variables

```powershell
# Set environment variable (per-user)
[Environment]::SetEnvironmentVariable("SMTP_PASSWORD", "your_password", "User")

# Modify config to reference environment variable
"Password": "$env:SMTP_PASSWORD"
```

#### Option C: Use OAuth2 (for Gmail/Office365)

Modern authentication methods are more secure than app passwords. Consider using Microsoft Graph API or Gmail API for production environments.

### 4. Domain List Management

Organize domains by priority or category:

```text
# Critical Production Domains
company.com
app.company.com
api.company.com

# Partner Domains
partner1.com
partner2.com

# Email Domains
mail.company.com
```

### 5. Monitoring Strategy

**Run frequency based on risk**:
- **High risk domains**: Every 2-4 hours
- **Standard domains**: Every 8-12 hours
- **Low risk domains**: Daily

**Stagger checks** if monitoring many domains to avoid hitting API limits.

## Troubleshooting

### Issue: "Configuration file not found"

**Solution**: Ensure `DomainMonitorConfig.json` is in the same directory as the script, or use `-ConfigFile` parameter with full path.

### Issue: "Please configure a valid VirusTotal API key"

**Solution**:
1. Get API key from https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
2. Update `ApiKey` in config file
3. Ensure the value doesn't contain extra quotes or spaces

### Issue: "Failed to send email"

**Solutions**:
- Verify SMTP server, port, and credentials
- Check firewall/antivirus blocking SMTP connections
- For Gmail: Use [App Password](https://support.google.com/accounts/answer/185833), not regular password
- Test with: `.\Monitor-DomainsWithVirusTotal.ps1 -SendTestEmail`

### Issue: "Rate limit exceeded" or HTTP 429 errors

**Solutions**:
- Increase `RateLimitDelayMs` (free tier: 15000+)
- Reduce number of domains per execution
- Upgrade to VirusTotal premium API

### Issue: No email sent, but threats detected

**Check**:
1. Review log file for email send errors
2. Verify spam/junk folders
3. Check email server logs
4. Test email with `-SendTestEmail` flag

### Issue: Too many false positives

**Solutions**:
- Increase thresholds: `MaliciousCount`, `SuspiciousCount`
- Lower `MinReputation` threshold
- Review VirusTotal categories to understand why domains are flagged

## Advanced Usage

### Custom Analysis Logic

Modify the `Test-DomainThreat` function to add custom logic:

```powershell
# Example: Only alert on specific categories
if ($attributes.Categories) {
    $criticalCategories = @('malware', 'phishing', 'ransomware')
    $foundCategories = $attributes.Categories.PSObject.Properties |
        Where-Object { $criticalCategories -contains $_.Value.ToLower() }

    if ($foundCategories) {
        $isThreat = $true
    }
}
```

### Multiple Configuration Files

Run different monitoring profiles:

```powershell
# Critical domains - check every 2 hours
.\Monitor-DomainsWithVirusTotal.ps1 -ConfigFile "config-critical.json"

# Standard domains - check every 8 hours
.\Monitor-DomainsWithVirusTotal.ps1 -ConfigFile "config-standard.json"
```

### Integration with SIEM/Logging Systems

Export results to JSON for SIEM ingestion:

```powershell
# Add to script to export results
$results | ConvertTo-Json -Depth 10 | Out-File "results-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
```

### Webhook Notifications

Instead of email, send to Slack/Teams/Discord:

```powershell
# Example: Slack webhook
$slackPayload = @{
    text = "VirusTotal Alert: $($threatenedDomains.Count) domains flagged"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" `
    -Method Post -Body $slackPayload -ContentType 'application/json'
```

## Security Considerations

1. **API Key Protection**: Never commit API keys to version control
2. **Password Storage**: Use encrypted storage or environment variables
3. **Log File Permissions**: Restrict access to log files (may contain sensitive data)
4. **Least Privilege**: Run scheduled task with minimum required permissions
5. **Audit Trail**: Keep logs for compliance and incident response

## Support & Documentation

- **VirusTotal API Docs**: https://docs.virustotal.com/reference/domain-info
- **VirusTotalAnalyzer Module**: https://evotec.xyz/working-with-virustotal-from-powershell/
- **Module GitHub**: https://github.com/EvotecIT/VirusTotalAnalyzer

## License

This script is provided as-is for use with the VirusTotalAnalyzer PowerShell module.

## Changelog

### Version 1.0 (2025-11-05)
- Initial release
- Domain monitoring with VirusTotal API
- Email alerting with HTML formatting
- Configurable thresholds
- Comprehensive logging
- Scheduled task support
