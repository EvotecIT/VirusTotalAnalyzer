using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Submission
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public SubmissionData Data { get; set; } = new();
}

public sealed class SubmissionData
{
    public SubmissionAttributes Attributes { get; set; } = new();
}

public sealed class SubmissionAttributes
{
    [JsonPropertyName("date")]
    public DateTimeOffset Date { get; set; }
}

public sealed class SubmissionsResponse
{
    [JsonPropertyName("data")]
    public List<Submission> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}
