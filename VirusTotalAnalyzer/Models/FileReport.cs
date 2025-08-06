using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public FileData Data { get; set; } = new();
}

public sealed class FileData
{
    public FileAttributes Attributes { get; set; } = new();
}

public sealed class FileAttributes
{
    [JsonPropertyName("md5")]
    public string Md5 { get; set; } = string.Empty;

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; set; }
}
