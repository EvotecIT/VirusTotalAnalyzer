# Use Ubuntu-based PowerShell image for better compatibility
# Specify platform for ARM64 compatibility
FROM --platform=linux/arm64 mcr.microsoft.com/powershell:7.4-ubuntu-22.04 AS base

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

# Create data directory for logs
RUN mkdir -p /app/data /app/config

# Set permissions
RUN chmod +x /app/Monitor-DomainsWithVirusTotal.ps1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pwsh -Command "exit 0"

# Default command - can be overridden
CMD ["pwsh", "-File", "/app/Monitor-DomainsWithVirusTotal.ps1", "-ConfigFile", "/app/config/DomainMonitorConfig.json"]
