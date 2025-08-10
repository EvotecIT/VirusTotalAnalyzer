using System.Collections.Generic;
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

public sealed class RetrohuntJobResponse
{
    [JsonPropertyName("data")]
    public RetrohuntJob? Data { get; set; }
}

public sealed class RetrohuntJobsResponse
{
    [JsonPropertyName("data")]
    public List<RetrohuntJob> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public Meta? Meta { get; set; }
}
