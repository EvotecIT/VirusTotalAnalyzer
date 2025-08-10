using System;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class RetrohuntJobRequest
{
    [JsonPropertyName("data")]
    public RetrohuntJobRequestData Data { get; set; } = new();
}

public sealed class RetrohuntJobRequestData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "retrohunt_job";

    [JsonPropertyName("attributes")]
    public RetrohuntJobRequestAttributes Attributes { get; set; } = new();
}

public sealed class RetrohuntJobRequestAttributes
{
    [JsonPropertyName("rules")]
    public string Rules { get; set; } = string.Empty;

    [JsonPropertyName("comment")]
    public string? Comment { get; set; }

    [JsonPropertyName("from")]
    public DateTimeOffset? From { get; set; }

    [JsonPropertyName("to")]
    public DateTimeOffset? To { get; set; }
}

