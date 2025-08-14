

namespace VirusTotalAnalyzer.Models;

public sealed class DomainWhois
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public DomainWhoisData Data { get; set; } = new();
}

public sealed class DomainWhoisData
{
    public DomainWhoisAttributes Attributes { get; set; } = new();
}

public sealed class DomainWhoisAttributes
{
    public string Whois { get; set; } = string.Empty;
}