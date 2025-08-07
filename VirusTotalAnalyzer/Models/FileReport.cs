using System.Collections.Generic;
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

    [JsonPropertyName("reputation")]
    public int Reputation { get; set; }

    [JsonPropertyName("creation_date")]
    public long CreationDate { get; set; }

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; } = new();

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; } = new();

    [JsonPropertyName("categories")]
    public Dictionary<string, Verdict> Categories { get; set; } = new();

    [JsonPropertyName("last_analysis_date")]
    public long LastAnalysisDate { get; set; }
}
