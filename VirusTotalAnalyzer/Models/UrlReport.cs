using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public UrlData Data { get; set; } = new();
}

public sealed class UrlData
{
    public UrlAttributes Attributes { get; set; } = new();
}

public sealed class UrlAttributes
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;
}
