# VTMonitoring - Coolify Deployment Directory

This directory contains the deployment files for running the VirusTotal Domain Monitor on Coolify.

## Contents

- **Dockerfile** - Container definition for PowerShell Core with VirusTotalAnalyzer module
- **docker-compose.yml** - Docker Compose service configuration (alternative deployment method)
- **.dockerignore** - Build optimization file
- **.env.example** - Environment variables template

## Quick Deploy to Coolify

### 1. Create New Resource

1. Go to Coolify Dashboard
2. Click "New Resource" → "Public Repository" (or Private with GitHub App)
3. Repository URL: `https://github.com/YOUR_USERNAME/VirusTotalAnalyzer`
4. Branch: `master`

### 2. Configure Build

- **Build Pack**: Dockerfile
- **Base Directory**: `VTMonitoring` ← **IMPORTANT!**
- **Dockerfile Location**: `Dockerfile` (default)

### 3. Set Environment Variables

Add these in Coolify UI (mark sensitive ones as "Secret"):

```bash
VIRUSTOTAL_API_KEY=your_api_key_here
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=monitoring@example.com
SMTP_PASSWORD=your_password_here
SMTP_FROM=monitoring@example.com
SMTP_TO=admin@example.com,security@example.com
SMTP_USE_SSL=true
THRESHOLD_MALICIOUS=0
THRESHOLD_SUSPICIOUS=3
THRESHOLD_MIN_REPUTATION=-10
RATE_LIMIT_DELAY_MS=15000
TZ=UTC
```

### 4. Deploy

Click "Deploy" and wait for the build to complete.

### 5. Add Scheduled Task

Navigate to "Scheduled Tasks" tab and add:

**Name**: Domain Monitor
**Command**:
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

**Frequency**: `0 */4 * * *` (every 4 hours)

### 6. Add Domains

Create `/app/domains/domains.txt` in the container with your domains (one per line):
```
example.com
mycompany.com
partner-site.com
```

## Documentation

- **Complete Deployment Guide**: See `../COOLIFY-DEPLOYMENT.md`
- **Quick Start Guide**: See `../Examples/COOLIFY-QUICKSTART.md`
- **Windows Deployment**: See `../Examples/DOMAIN-MONITORING-README.md`

## File Structure

```
VirusTotalAnalyzer/
├── VTMonitoring/           ← You are here (Coolify base directory)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── .dockerignore
│   ├── .env.example
│   └── README.md
├── Examples/               ← PowerShell scripts and configs
│   ├── Monitor-DomainsWithVirusTotal.ps1
│   ├── DomainMonitorConfig.json
│   ├── domains.txt
│   ├── DOMAIN-MONITORING-README.md
│   └── COOLIFY-QUICKSTART.md
└── COOLIFY-DEPLOYMENT.md   ← Comprehensive deployment guide
```

## Troubleshooting

**Build fails**: Ensure "Base Directory" is set to `VTMonitoring` in Coolify

**Module not found**: Check Dockerfile installs VirusTotalAnalyzer module

**No emails sent**: Verify SMTP settings, check spam folder, test with `-SendTestEmail`

For more help, see the main deployment guide: `../COOLIFY-DEPLOYMENT.md`
