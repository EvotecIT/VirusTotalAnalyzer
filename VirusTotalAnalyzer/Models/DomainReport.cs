using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public DomainData Data { get; set; } = new();
}

public sealed class DomainData
{
    public DomainAttributes Attributes { get; set; } = new();
}

public sealed class DomainAttributes
{
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;
}
