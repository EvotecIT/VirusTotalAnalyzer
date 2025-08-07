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

    [JsonPropertyName("sha1")]
    public string? Sha1 { get; set; }

    [JsonPropertyName("reputation")]
    public int Reputation { get; set; }

    [JsonPropertyName("creation_date")]
    public long CreationDate { get; set; }

    [JsonPropertyName("first_submission_date")]
    public long FirstSubmissionDate { get; set; }

    [JsonPropertyName("last_submission_date")]
    public long LastSubmissionDate { get; set; }

    [JsonPropertyName("times_submitted")]
    public int TimesSubmitted { get; set; }

    [JsonPropertyName("unique_sources")]
    public int UniqueSources { get; set; }

    [JsonPropertyName("size")]
    public long Size { get; set; }

    [JsonPropertyName("last_modification_date")]
    public long LastModificationDate { get; set; }

    [JsonPropertyName("meaningful_name")]
    public string? MeaningfulName { get; set; }

    [JsonPropertyName("type_description")]
    public string? TypeDescription { get; set; }

    [JsonPropertyName("type_tag")]
    public string? TypeTag { get; set; }

    [JsonPropertyName("type_extension")]
    public string? TypeExtension { get; set; }

    [JsonPropertyName("ssdeep")]
    public string? Ssdeep { get; set; }

    [JsonPropertyName("magic")]
    public string? Magic { get; set; }

    [JsonPropertyName("names")]
    public List<string> Names { get; set; } = new();

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    [JsonPropertyName("crowdsourced_verdicts")]
    public List<CrowdSourcedVerdict> CrowdSourcedVerdicts { get; set; } = new();

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
