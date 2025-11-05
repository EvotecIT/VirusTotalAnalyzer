# Deploying VirusTotal Domain Monitor on Coolify

This guide walks you through deploying the VirusTotal Domain Monitor as a scheduled task on [Coolify](https://coolify.io), a self-hosted alternative to Heroku/Vercel.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Deployment Methods](#deployment-methods)
  - [Method 1: Scheduled Task (Recommended)](#method-1-scheduled-task-recommended)
  - [Method 2: Docker Compose Service](#method-2-docker-compose-service)
- [Configuration](#configuration)
- [Monitoring & Troubleshooting](#monitoring--troubleshooting)
- [Scaling & Optimization](#scaling--optimization)

---

## Overview

Running the VirusTotal Domain Monitor on Coolify provides:

- **Automated Scheduling**: Use Coolify's built-in scheduled tasks feature
- **Centralized Management**: Manage environment variables and secrets through the UI
- **Scalability**: Run on your own infrastructure (cloud or on-premises)
- **Cost Efficiency**: No per-execution fees like traditional serverless platforms
- **Containerized**: Runs in Docker containers for consistency
- **Self-Hosted**: Full control over your monitoring infrastructure

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Coolify Platform                   │
│  ┌──────────────────────────────────────────┐  │
│  │       Scheduled Task Trigger             │  │
│  │    (Cron: */4 * * * * = Every 4 hours)   │  │
│  └──────────────┬───────────────────────────┘  │
│                 │                                │
│                 ▼                                │
│  ┌──────────────────────────────────────────┐  │
│  │   PowerShell Core Container              │  │
│  │                                          │  │
│  │  ┌────────────────────────────────────┐ │  │
│  │  │  Monitor-DomainsWithVirusTotal.ps1 │ │  │
│  │  │                                    │ │  │
│  │  │  1. Read domains from volume       │ │  │
│  │  │  2. Query VirusTotal API           │ │  │
│  │  │  3. Analyze threat scores          │ │  │
│  │  │  4. Send email if threats found   │ │  │
│  │  │  5. Write logs to volume           │ │  │
│  │  └────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────┘  │
│                                                  │
│  Persistent Volumes:                             │
│  • /app/domains  → domains.txt                   │
│  • /app/config   → Generated from env vars       │
│  • /app/data     → Logs                          │
└─────────────────────────────────────────────────┘
```

---

## Prerequisites

### 1. Coolify Instance

You need a running Coolify instance. Options:

- **Cloud VPS**: DigitalOcean, Linode, Hetzner, AWS EC2, etc.
- **On-Premises**: Local server or homelab
- **Coolify Cloud**: Use Coolify's managed hosting (if available)

**Installation**: Follow the [Coolify installation guide](https://coolify.io/docs/installation)

### 2. Git Repository

Your code must be in a Git repository (GitHub, GitLab, Gitea, etc.). Options:

- **Public Repository**: Can be accessed without authentication
- **Private Repository**: Requires GitHub App or Deploy Key setup in Coolify

### 3. VirusTotal API Key

Get your free API key:
1. Register at [VirusTotal](https://www.virustotal.com/)
2. Navigate to [API Key page](https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey)
3. Copy your API key

**Limits**: Free tier = 4 requests/min, 500 requests/day

### 4. SMTP Email Server

For sending alerts, you need SMTP credentials:

- **Gmail**: Use [App Password](https://support.google.com/accounts/answer/185833) (`smtp.gmail.com:587`)
- **Outlook/Office365**: `smtp.office365.com:587`
- **SendGrid**: `smtp.sendgrid.net:587`
- **Custom SMTP**: Your organization's mail server

---

## Deployment Methods

### Method 1: Scheduled Task (Recommended)

This method uses Coolify's built-in scheduled tasks feature to run the monitoring script periodically.

#### Step 1: Create New Resource in Coolify

1. **Log into Coolify** dashboard
2. Navigate to your **Project**
3. Click **"+ New Resource"**
4. Select **"Public Repository"** (or GitHub App/Deploy Key for private repos)

#### Step 2: Configure Repository

1. **Paste Repository URL**:
   ```
   https://github.com/YOUR_USERNAME/VirusTotalAnalyzer
   ```

2. **Select Branch**: `main` or your feature branch

3. **Choose Build Pack**: Select **"Dockerfile"**

4. **Base Directory**: `/` (root) or leave empty

5. Click **"Continue"**

#### Step 3: Configure Environment Variables

In the Coolify UI, navigate to **Environment Variables** and add:

```bash
# VirusTotal API
VIRUSTOTAL_API_KEY=your_actual_api_key_here

# SMTP Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=monitoring@example.com
SMTP_PASSWORD=your_smtp_password_here
SMTP_FROM=monitoring@example.com
SMTP_TO=admin@example.com,security@example.com
SMTP_CC=
SMTP_USE_SSL=true

# Thresholds
THRESHOLD_MALICIOUS=0
THRESHOLD_SUSPICIOUS=3
THRESHOLD_MIN_REPUTATION=-10

# Rate Limiting
RATE_LIMIT_DELAY_MS=15000

# Timezone
TZ=America/New_York
```

**Important Security Notes**:
- ✅ Mark sensitive variables (API keys, passwords) as **"Secret"** in Coolify
- ✅ These will be encrypted and hidden in the UI
- ❌ Never commit `.env` files with real credentials to Git

#### Step 4: Create Domains File Volume

You need to provide the list of domains to monitor. In Coolify:

1. Navigate to **Storage** section
2. Click **"Add Storage"**
3. Configure:
   - **Name**: `domain-monitor-domains`
   - **Type**: Choose volume type
   - **Mount Path**: `/app/domains`

4. **Create the domains.txt file**:
   - After deployment, access the container
   - Create `/app/domains/domains.txt` with your domains (one per line):
     ```
     example.com
     mycompany.com
     partner-site.com
     ```

**Alternative**: You can modify the Dockerfile to copy domains.txt from the repository:
```dockerfile
COPY Examples/domains.txt /app/domains/domains.txt
```

#### Step 5: Configure Scheduled Task

1. Navigate to **"Scheduled Tasks"** tab in your application
2. Click **"Add Scheduled Task"**
3. Configure:
   - **Name**: `VirusTotal Domain Monitor`
   - **Container**: `domain-monitor` (if you have multiple containers)
   - **Command**:
     ```bash
     pwsh -File /app/Monitor-DomainsWithVirusTotal.ps1 -ConfigFile /app/config/DomainMonitorConfig.json
     ```
   - **Frequency**: Choose one:
     - **Predefined**: `@every_4_hours` or use custom cron
     - **Cron Syntax**:
       - Every 4 hours: `0 */4 * * *`
       - Every 6 hours: `0 */6 * * *`
       - Twice daily (8am & 8pm): `0 8,20 * * *`
       - Every day at 9am: `0 9 * * *`

4. Click **"Save"**

#### Step 6: Deploy

1. Click **"Deploy"** in the Coolify UI
2. Monitor the build logs
3. Wait for deployment to complete

#### Step 7: Test

To test immediately without waiting for the schedule:

1. Navigate to **"Scheduled Tasks"**
2. Click **"Run Now"** on your task
3. Check logs for execution

---

### Method 2: Docker Compose Service

Alternative approach using Docker Compose with an external cron container.

#### Step 1: Use Docker Compose Build Pack

1. Create resource as before
2. Select **"Docker Compose"** as build pack instead of Dockerfile

#### Step 2: Coolify Will Use docker-compose.yml

The `docker-compose.yml` in the repository will be used automatically.

#### Step 3: Configure Volumes

You'll need to manually create volumes in Coolify or modify the docker-compose.yml to use Coolify's volume syntax:

```yaml
volumes:
  domain-monitor-logs:
    driver: local
    driver_opts:
      type: none
      device: /var/lib/coolify/storage/domain-monitor/logs
      o: bind
```

#### Step 4: Set Up External Cron (on Coolify Server)

Since the compose file sets `restart: "no"`, you'll need to trigger it externally:

1. SSH into your Coolify server
2. Add to crontab:
   ```bash
   # Every 4 hours
   0 */4 * * * docker compose -f /path/to/docker-compose.yml up domain-monitor
   ```

**Note**: This method is more complex and less integrated with Coolify. Method 1 is recommended.

---

## Configuration

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VIRUSTOTAL_API_KEY` | ✅ Yes | - | Your VirusTotal API key |
| `SMTP_SERVER` | ✅ Yes | - | SMTP server hostname |
| `SMTP_PORT` | ✅ Yes | `587` | SMTP port |
| `SMTP_USERNAME` | ✅ Yes | - | SMTP authentication username |
| `SMTP_PASSWORD` | ✅ Yes | - | SMTP authentication password |
| `SMTP_FROM` | ✅ Yes | - | Sender email address |
| `SMTP_TO` | ✅ Yes | - | Recipient emails (comma-separated) |
| `SMTP_CC` | ❌ No | - | CC emails (comma-separated) |
| `SMTP_USE_SSL` | ❌ No | `true` | Enable SSL/TLS |
| `THRESHOLD_MALICIOUS` | ❌ No | `0` | Max malicious detections before alert |
| `THRESHOLD_SUSPICIOUS` | ❌ No | `3` | Max suspicious detections before alert |
| `THRESHOLD_MIN_REPUTATION` | ❌ No | `-10` | Minimum reputation score |
| `RATE_LIMIT_DELAY_MS` | ❌ No | `15000` | Delay between API requests (ms) |
| `TZ` | ❌ No | `UTC` | Timezone for logs |

### Using Coolify Shared Variables

Coolify supports hierarchical shared variables:

**Team-level variables** (set once, use across all projects):
```bash
# In Coolify UI: Team Settings → Environment Variables
SMTP_SERVER=smtp.company.com
SMTP_FROM=monitoring@company.com
```

**Reference in your application**:
```bash
SMTP_SERVER={{team.SMTP_SERVER}}
SMTP_FROM={{team.SMTP_FROM}}
```

**Project-level variables**:
```bash
# Reference as:
VIRUSTOTAL_API_KEY={{project.VIRUSTOTAL_API_KEY}}
```

**Environment-level** (production vs staging):
```bash
SMTP_TO={{environment.ADMIN_EMAIL}}
```

### Domains File Management

**Option A: Volume-based (Recommended)**
- Create a persistent volume at `/app/domains`
- Edit `domains.txt` via SSH or file manager
- Changes persist across deployments

**Option B: Repository-based**
- Store `domains.txt` in your Git repository
- Modify Dockerfile: `COPY your-domains.txt /app/domains/domains.txt`
- Update domains by committing to Git and redeploying

**Option C: Dynamic/API-based**
- Modify the script to fetch domains from an API or database
- Useful for managing hundreds of domains

---

## Monitoring & Troubleshooting

### Viewing Logs

**Coolify UI Logs**:
1. Navigate to your application
2. Click **"Logs"** tab
3. View real-time container logs

**Persistent Log File**:
- Logs are written to `/app/data/DomainMonitor.log`
- Access via volume mount or container shell

**Access Container Shell**:
```bash
# From Coolify UI: click "Terminal" button
# Or via SSH:
docker exec -it virustotal-domain-monitor pwsh
```

### Common Issues

#### Issue: "Module VirusTotalAnalyzer not found"

**Solution**:
- Rebuild the container
- Check Dockerfile installs the module correctly
- Verify PowerShell module installation:
  ```bash
  docker exec -it virustotal-domain-monitor pwsh -Command "Get-Module -ListAvailable"
  ```

#### Issue: "Configuration file not found"

**Solution**:
- Verify environment variables are set in Coolify
- Check the command generates config correctly
- Inspect container: `docker exec -it virustotal-domain-monitor ls -la /app/config/`

#### Issue: "No domains found"

**Solution**:
- Verify `/app/domains/domains.txt` exists and has content
- Check volume mount: `docker exec -it virustotal-domain-monitor cat /app/domains/domains.txt`
- Ensure line endings are Unix-style (LF, not CRLF)

#### Issue: "Failed to send email"

**Solution**:
- Test SMTP settings outside Coolify first
- Check firewall rules (outbound port 587/465)
- For Gmail: Use App Password, not regular password
- Verify SMTP_USE_SSL matches your server's requirements

#### Issue: "Rate limit exceeded"

**Solution**:
- Increase `RATE_LIMIT_DELAY_MS` to 15000+ (free tier)
- Reduce number of domains per run
- Upgrade to VirusTotal premium API

### Testing Deployment

**Test email configuration**:
```bash
# Run one-time test email
docker exec -it virustotal-domain-monitor pwsh -File /app/Monitor-DomainsWithVirusTotal.ps1 -ConfigFile /app/config/DomainMonitorConfig.json -SendTestEmail
```

**Manual execution**:
```bash
# Trigger manual check
docker exec -it virustotal-domain-monitor pwsh -File /app/Monitor-DomainsWithVirusTotal.ps1 -ConfigFile /app/config/DomainMonitorConfig.json
```

**Check container status**:
```bash
docker ps -a | grep virustotal
docker logs virustotal-domain-monitor
```

---

## Scaling & Optimization

### Managing Multiple Domain Lists

Run separate scheduled tasks for different priority levels:

**High Priority Domains** (every 2 hours):
- Create `/app/domains/critical-domains.txt`
- Scheduled task: `0 */2 * * *`
- Command: `pwsh -File /app/Monitor-DomainsWithVirusTotal.ps1 -ConfigFile /app/config/DomainMonitorConfig.json -DomainsFile /app/domains/critical-domains.txt`

**Standard Domains** (every 6 hours):
- Create `/app/domains/standard-domains.txt`
- Scheduled task: `0 */6 * * *`

### API Quota Management

**Free Tier Optimization**:
- **4 requests/min** = max 240 requests/hour
- **500 requests/day** = max ~20 domains/hour if checking every 4 hours
- Strategy: Rotate domain checks across multiple runs

**Implementing Rotation**:
```bash
# Check first 20 domains on even hours
0 */2 * * * [...command...] -DomainsFile /app/domains/batch-1.txt

# Check next 20 domains on odd hours
0 1-23/2 * * * [...command...] -DomainsFile /app/domains/batch-2.txt
```

**Premium Tier**:
- 1000 requests/min
- Can monitor thousands of domains per run
- Reduce `RATE_LIMIT_DELAY_MS` to 100-1000ms

### Multi-Region Deployment

Deploy to multiple Coolify instances for redundancy:

```
┌─────────────────┐      ┌─────────────────┐
│  Coolify US     │      │  Coolify EU     │
│  (Primary)      │      │  (Backup)       │
│  Run: 0,4,8,12, │      │  Run: 2,6,10,14,│
│       16,20 hrs │      │       18,22 hrs │
└─────────────────┘      └─────────────────┘
```

### Resource Limits

Set resource limits in Coolify to prevent runaway containers:

```yaml
# In docker-compose.yml (if using Method 2)
services:
  domain-monitor:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
```

---

## Advanced Configuration

### Webhook Integration (Slack/Teams/Discord)

Modify the script to send to webhooks instead of/in addition to email:

```powershell
# Add to script
$webhookUrl = $env:SLACK_WEBHOOK_URL
$payload = @{
    text = "VirusTotal Alert: $($threatenedDomains.Count) domains flagged"
    attachments = @(
        @{
            color = "danger"
            fields = @(
                @{ title = "Domain"; value = $threat.Domain; short = $true }
                @{ title = "Malicious"; value = $threat.Analysis.Stats.Malicious; short = $true }
            )
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json'
```

### Database Integration

Store results in a database for historical analysis:

```powershell
# Install PostgreSQL module
Install-Module -Name PostgreSQL -Force

# Connect and insert
$results | ForEach-Object {
    Invoke-SqlQuery -Connection $conn -Query @"
        INSERT INTO domain_scans (domain, malicious_count, reputation, scan_time)
        VALUES ('$($_.Domain)', $($_.Stats.Malicious), $($_.Reputation), NOW())
"@
}
```

### Metrics & Monitoring

Export metrics to Prometheus:

1. Add a metrics endpoint to your container
2. Configure Prometheus scraping in Coolify
3. Visualize in Grafana

---

## Security Best Practices

### 1. Secret Management

✅ **DO**:
- Use Coolify's built-in secret management
- Mark sensitive variables as "Secret"
- Rotate API keys and passwords regularly

❌ **DON'T**:
- Commit `.env` files with real credentials
- Log sensitive data
- Use weak SMTP passwords

### 2. Network Security

- **Restrict outbound**: Only allow connections to VirusTotal API and SMTP server
- **Use private networks**: Keep containers on Coolify's internal network
- **Enable HTTPS**: Use SSL/TLS for SMTP

### 3. Access Control

- **Coolify RBAC**: Use role-based access control
- **SSH key auth**: Disable password authentication
- **Audit logs**: Review Coolify access logs regularly

### 4. Container Security

- **Non-root user**: Run containers as non-root (already done in Dockerfile)
- **Read-only volumes**: Mount config as read-only (`:ro`)
- **Image scanning**: Scan PowerShell base image for vulnerabilities

---

## Cost Comparison

Running on Coolify vs. traditional serverless:

| Platform | Cost (monthly) | Notes |
|----------|----------------|-------|
| **Coolify (self-hosted)** | $5-20 | VPS cost (DigitalOcean, Hetzner, etc.) |
| AWS Lambda | $0-5 | Free tier: 1M requests/mo |
| Azure Functions | $0-10 | Consumption plan |
| Google Cloud Functions | $0-8 | Free tier: 2M invocations/mo |

**Advantages of Coolify**:
- Predictable costs
- No cold starts
- Full control
- Run multiple services on same infrastructure

**When to use traditional serverless**:
- Very low execution frequency (<10/day)
- No infrastructure management desired
- Need massive scale (100k+ executions/day)

---

## Backup & Disaster Recovery

### Backup Strategy

**1. Configuration Backup**:
```bash
# Export environment variables from Coolify
# Store in secure location (KeePass, 1Password, etc.)
```

**2. Domains List Backup**:
```bash
# Backup domains.txt regularly
docker cp virustotal-domain-monitor:/app/domains/domains.txt ./backup/
```

**3. Log Archival**:
```bash
# Archive logs monthly
docker cp virustotal-domain-monitor:/app/data/DomainMonitor.log ./archive/$(date +%Y-%m).log
```

### Restore Procedure

1. Redeploy from Git repository
2. Restore environment variables in Coolify UI
3. Restore `domains.txt` to volume
4. Reconfigure scheduled tasks

---

## Support & Resources

- **Coolify Documentation**: https://coolify.io/docs
- **Coolify Discord**: https://coolify.io/discord
- **VirusTotal API Docs**: https://docs.virustotal.com/reference/domain-info
- **VirusTotalAnalyzer Module**: https://evotec.xyz/working-with-virustotal-from-powershell/
- **PowerShell Core**: https://github.com/PowerShell/PowerShell

---

## Changelog

### Version 1.0 (2025-11-05)
- Initial Coolify deployment guide
- Dockerfile for PowerShell Core
- Docker Compose configuration
- Scheduled task setup
- Environment variable configuration

---

## License

This deployment guide and associated scripts are provided as-is for use with the VirusTotalAnalyzer PowerShell module.
