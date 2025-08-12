using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class IpWhois
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public IpWhoisData Data { get; set; } = new();
}

public sealed class IpWhoisData
{
    public IpWhoisAttributes Attributes { get; set; } = new();
}

public sealed class IpWhoisAttributes
{
    [JsonPropertyName("whois")]
    public string Whois { get; set; } = string.Empty;
}
