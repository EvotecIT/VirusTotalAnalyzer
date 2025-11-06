#!/bin/bash
set -e

echo "=== VirusTotal Domain Monitor Entrypoint ==="
echo "Initializing container..."

# Create config directory if it doesn't exist
mkdir -p /app/config /app/data /app/domains

# Generate config file from environment variables
echo "Generating configuration from environment variables..."
pwsh -Command "
\$config = @{
  ApiKey = '\$env:VIRUSTOTAL_API_KEY'
  DomainsFile = '/app/domains/domains.txt'
  LogFile = '/app/data/DomainMonitor.log'
  RateLimitDelayMs = if (\$env:RATE_LIMIT_DELAY_MS) { [int]\$env:RATE_LIMIT_DELAY_MS } else { 15000 }
  Thresholds = @{
    MaliciousCount = if (\$env:THRESHOLD_MALICIOUS) { [int]\$env:THRESHOLD_MALICIOUS } else { 0 }
    SuspiciousCount = if (\$env:THRESHOLD_SUSPICIOUS) { [int]\$env:THRESHOLD_SUSPICIOUS } else { 3 }
    MinReputation = if (\$env:THRESHOLD_MIN_REPUTATION) { [int]\$env:THRESHOLD_MIN_REPUTATION } else { -10 }
  }
  EmailSettings = @{
    From = '\$env:SMTP_FROM'
    To = if (\$env:SMTP_TO) { (\$env:SMTP_TO -split ',') | ForEach-Object { \$_.Trim() } } else { @() }
    Cc = if (\$env:SMTP_CC) { (\$env:SMTP_CC -split ',') | ForEach-Object { \$_.Trim() } } else { @() }
    SmtpServer = '\$env:SMTP_SERVER'
    Port = if (\$env:SMTP_PORT) { [int]\$env:SMTP_PORT } else { 587 }
    UseSsl = if (\$env:SMTP_USE_SSL -eq 'false') { \$false } else { \$true }
    Username = '\$env:SMTP_USERNAME'
    Password = '\$env:SMTP_PASSWORD'
  }
}

\$config | ConvertTo-Json -Depth 10 | Set-Content '/app/config/DomainMonitorConfig.json'
Write-Host 'Configuration file created successfully'
"

# Check if config was created successfully
if [ ! -f /app/config/DomainMonitorConfig.json ]; then
    echo "ERROR: Failed to create configuration file"
    exit 1
fi

echo "Configuration created at /app/config/DomainMonitorConfig.json"

# Create default domains.txt if it doesn't exist
if [ ! -f /app/domains/domains.txt ]; then
    echo "No domains.txt found, creating from template..."
    cp /app/domains-template.txt /app/domains/domains.txt
    echo "Default domains.txt created. Update with your own domains."
fi

# Validate that domains.txt exists and has content
if [ ! -s /app/domains/domains.txt ]; then
    echo "WARNING: domains.txt is empty. Add domains to monitor."
fi

echo "Starting VirusTotal Domain Monitor..."
echo "---"

# Execute the monitoring script (or any command passed to the container)
exec "$@"
