using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class PrivateAnalysis
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public PrivateAnalysisData Data { get; set; } = new();
}

public sealed class PrivateAnalysisData
{
    public PrivateAnalysisAttributes Attributes { get; set; } = new();
}

public sealed class PrivateAnalysisAttributes
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
