using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileClassification
{
    [JsonPropertyName("data")]
    public FileClassificationData Data { get; set; } = new();
}

public sealed class FileClassificationData
{
    [JsonPropertyName("attributes")]
    public FileClassificationAttributes Attributes { get; set; } = new();
}

public sealed class FileClassificationAttributes
{
    [JsonPropertyName("classification")]
    public ClassificationResult Classification { get; set; } = new();
}

public sealed class ClassificationResult
{
    [JsonPropertyName("label")]
    public string? Label { get; set; }
}
