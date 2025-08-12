using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileClassification
{
    [JsonPropertyName("data")]
    public FileClassificationData Data { get; set; } = new();
}

public sealed class FileClassificationData
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("attributes")]
    public FileClassificationAttributes Attributes { get; set; } = new();
}

public sealed class FileClassificationAttributes
{
    [JsonPropertyName("popular_threat_name")]
    public string? PopularThreatName { get; set; }

    [JsonPropertyName("popular_threat_category")]
    public string? PopularThreatCategory { get; set; }

    [JsonPropertyName("suggested_threat_label")]
    public string? SuggestedThreatLabel { get; set; }
}

