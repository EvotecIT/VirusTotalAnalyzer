# Coolify Deployment - Quick Start

Get the VirusTotal Domain Monitor running on Coolify in 5 minutes.

## Prerequisites

- ✅ Running Coolify instance
- ✅ VirusTotal API key ([get it here](https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey))
- ✅ SMTP credentials for email alerts
- ✅ This repository (forked or cloned)

## Quick Deploy Steps

### 1. Create New Resource in Coolify

1. Log into Coolify dashboard
2. Navigate to your Project → Environment
3. Click **"+ New Resource"**
4. Select **"Public Repository"** (or Private with GitHub App)
5. Paste repository URL: `https://github.com/YOUR_USERNAME/VirusTotalAnalyzer`
6. Click **Continue**

### 2. Configure Build

1. **Build Pack**: Select **"Dockerfile"**
2. **Branch**: `main` (or your branch)
3. **Base Directory**: `/` (leave empty for root)
4. Click **Continue**

### 3. Set Environment Variables

Click **"Environment Variables"** and add these (mark secrets as "Secret"):

```bash
# Required Variables
VIRUSTOTAL_API_KEY=your_api_key_here
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=monitoring@example.com
SMTP_PASSWORD=your_password_here
SMTP_FROM=monitoring@example.com
SMTP_TO=admin@example.com,security@example.com
SMTP_USE_SSL=true

# Optional (use defaults if not set)
THRESHOLD_MALICIOUS=0
THRESHOLD_SUSPICIOUS=3
THRESHOLD_MIN_REPUTATION=-10
RATE_LIMIT_DELAY_MS=15000
TZ=UTC
```

### 4. Create Domains File

Before first run, you need to add domains to monitor:

**Option A: Add via Coolify UI** (after deployment)
1. Navigate to **Storage** tab
2. Click **"Add Storage"**
3. Mount point: `/app/domains`
4. Create file: `domains.txt` with your domains (one per line)

**Option B: Include in repository** (easier)
1. Edit `Examples/domains.txt` in your repository
2. Add your domains (one per line):
   ```
   example.com
   mycompany.com
   partner-site.com
   ```
3. Commit and push
4. Update Dockerfile to copy it:
   ```dockerfile
   COPY Examples/domains.txt /app/domains/domains.txt
   ```

### 5. Deploy

1. Click **"Deploy"** button
2. Wait for build to complete (2-3 minutes)
3. Check logs for any errors

### 6. Add Scheduled Task

1. Navigate to **"Scheduled Tasks"** tab
2. Click **"Add Scheduled Task"**
3. Configure:
   - **Name**: `Domain Monitor`
   - **Command**:
     ```bash
     pwsh -Command "
       \$config = @{
         ApiKey = '\$env:VIRUSTOTAL_API_KEY'
         DomainsFile = '/app/domains/domains.txt'
         LogFile = '/app/data/DomainMonitor.log'
         RateLimitDelayMs = [int]\$env:RATE_LIMIT_DELAY_MS
         Thresholds = @{
           MaliciousCount = [int]\$env:THRESHOLD_MALICIOUS
           SuspiciousCount = [int]\$env:THRESHOLD_SUSPICIOUS
           MinReputation = [int]\$env:THRESHOLD_MIN_REPUTATION
         }
         EmailSettings = @{
           From = '\$env:SMTP_FROM'
           To = (\$env:SMTP_TO -split ',').Trim()
           SmtpServer = '\$env:SMTP_SERVER'
           Port = [int]\$env:SMTP_PORT
           UseSsl = [bool]::Parse('\$env:SMTP_USE_SSL')
           Username = '\$env:SMTP_USERNAME'
           Password = '\$env:SMTP_PASSWORD'
         }
       }
       \$config | ConvertTo-Json -Depth 10 | Set-Content '/app/config/DomainMonitorConfig.json'
       & /app/Monitor-DomainsWithVirusTotal.ps1 -ConfigFile '/app/config/DomainMonitorConfig.json'
     "
     ```
   - **Frequency**: Select one:
     - `0 */4 * * *` (every 4 hours)
     - `0 */6 * * *` (every 6 hours)
     - `0 9,21 * * *` (twice daily at 9am & 9pm)

4. Click **"Save"**

### 7. Test

**Test the scheduled task**:
1. Go to **"Scheduled Tasks"** tab
2. Click **"Run Now"** button
3. Check logs for execution

**Test email configuration**:
```bash
# Access container terminal in Coolify UI, then run:
pwsh -Command "
  # Configure from env vars (same as above)
  \$config = @{ ... }
  \$config | ConvertTo-Json -Depth 10 | Set-Content '/app/config/DomainMonitorConfig.json'

  # Send test email
  & /app/Monitor-DomainsWithVirusTotal.ps1 -ConfigFile '/app/config/DomainMonitorConfig.json' -SendTestEmail
"
```

## Schedule Recommendations

Based on your needs:

| Use Case | Schedule | Cron |
|----------|----------|------|
| High security | Every 2 hours | `0 */2 * * *` |
| Standard monitoring | Every 4 hours | `0 */4 * * *` |
| Daily check | Once per day | `0 9 * * *` |
| Business hours only | Every 4h, 9am-5pm | `0 9-17/4 * * *` |

## Troubleshooting

### Build Fails

**Error**: `Module not found`
- Check Dockerfile installs VirusTotalAnalyzer
- Rebuild with cache cleared

**Error**: `Configuration file not found`
- Verify environment variables are set
- Check command in scheduled task generates config

### No Emails Sent

- Test SMTP with a simple script first
- For Gmail: Use [App Password](https://support.google.com/accounts/answer/185833)
- Check spam/junk folders
- Verify firewall allows outbound on port 587/465

### No Domains File

- Ensure domains.txt exists in `/app/domains/`
- Check volume mounts in Storage tab
- Or modify Dockerfile to COPY from repository

### Rate Limit Errors

- Increase `RATE_LIMIT_DELAY_MS` to 15000 or higher
- Free tier: 4 requests/min = 15 seconds between requests
- Reduce number of domains per check

## What's Next?

- 📚 Read [Full Deployment Guide](../COOLIFY-DEPLOYMENT.md) for advanced configuration
- 📧 Configure email templates and thresholds
- 📊 Set up monitoring and alerting
- 🔐 Review security best practices

## Support

- **Coolify Docs**: https://coolify.io/docs
- **Coolify Discord**: https://coolify.io/discord
- **VirusTotal API**: https://docs.virustotal.com/reference/domain-info

---

**Need help?** Check the [full deployment guide](../COOLIFY-DEPLOYMENT.md) or open an issue on GitHub.
