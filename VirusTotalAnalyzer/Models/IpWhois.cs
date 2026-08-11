

namespace VirusTotalAnalyzer.Models;

public sealed class IpWhois
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public IpWhoisAttributes Attributes { get; set; } = new();
}

public sealed class IpWhoisAttributes
{
    public string Whois { get; set; } = string.Empty;
}
