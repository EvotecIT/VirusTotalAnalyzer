using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class IpAddressReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public IpAddressData Data { get; set; } = new();
}

public sealed class IpAddressData
{
    public IpAddressAttributes Attributes { get; set; } = new();
}

public sealed class IpAddressAttributes
{
    [JsonPropertyName("ip_address")]
    public string IpAddress { get; set; } = string.Empty;
}
