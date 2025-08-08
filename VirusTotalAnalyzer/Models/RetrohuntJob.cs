using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class RetrohuntJob
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public RetrohuntJobData Data { get; set; } = new();
}

public sealed class RetrohuntJobData
{
    public RetrohuntJobAttributes Attributes { get; set; } = new();
}

public sealed class RetrohuntJobAttributes
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}
