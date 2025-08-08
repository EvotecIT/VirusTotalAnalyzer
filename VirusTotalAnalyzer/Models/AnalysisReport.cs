using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public AnalysisData Data { get; set; } = new();
}

public sealed class AnalysisData
{
    public AnalysisAttributes Attributes { get; set; } = new();
}

public sealed class AnalysisAttributes
{
    [JsonPropertyName("status")]
    public AnalysisStatus Status { get; set; }

    [JsonPropertyName("stats")]
    public AnalysisStats Stats { get; set; } = new();

    [JsonPropertyName("results")]
    public Dictionary<string, AnalysisResult> Results { get; set; } = new();

    [JsonPropertyName("date")]
    public DateTimeOffset Date { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}
