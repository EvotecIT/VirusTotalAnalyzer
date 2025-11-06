# Use Ubuntu-based PowerShell image for better compatibility
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04 AS base

# Install required dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    tzdata \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install VirusTotalAnalyzer module
RUN pwsh -Command "Install-Module -Name VirusTotalAnalyzer -Force -Scope AllUsers -Verbose"

# Copy scripts and configuration
COPY Examples/Monitor-DomainsWithVirusTotal.ps1 /app/
COPY Examples/DomainMonitorConfig.json /app/config-template.json
COPY Examples/domains.txt /app/domains-template.txt
COPY entrypoint.sh /app/

# Create data directory for logs
RUN mkdir -p /app/data /app/config /app/domains

# Set permissions
RUN chmod +x /app/Monitor-DomainsWithVirusTotal.ps1 && \
    chmod +x /app/entrypoint.sh

# Environment variable defaults
ENV CHECK_INTERVAL_MINUTES=60 \
    THRESHOLD_MALICIOUS=0 \
    THRESHOLD_SUSPICIOUS=3 \
    THRESHOLD_MIN_REPUTATION=-10 \
    RATE_LIMIT_DELAY_MS=15000

# Health check - verify the entrypoint process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f "entrypoint.sh" > /dev/null || exit 1

# Set entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command - can be overridden
CMD ["pwsh", "-File", "/app/Monitor-DomainsWithVirusTotal.ps1", "-ConfigFile", "/app/config/DomainMonitorConfig.json"]
