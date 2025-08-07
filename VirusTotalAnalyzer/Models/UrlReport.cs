using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public UrlData Data { get; set; } = new();
}

public sealed class UrlData
{
    public UrlAttributes Attributes { get; set; } = new();
}

public sealed class UrlAttributes
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("reputation")]
    public int Reputation { get; set; }

    [JsonPropertyName("creation_date")]
    public long CreationDate { get; set; }

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    [JsonPropertyName("first_submission_date")]
    public long FirstSubmissionDate { get; set; }

    [JsonPropertyName("last_submission_date")]
    public long LastSubmissionDate { get; set; }

    [JsonPropertyName("last_modification_date")]
    public long LastModificationDate { get; set; }

    [JsonPropertyName("times_submitted")]
    public int TimesSubmitted { get; set; }

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

    [JsonPropertyName("crowdsourced_verdicts")]
    public List<CrowdsourcedVerdict> CrowdsourcedVerdicts { get; set; } = new();
}
