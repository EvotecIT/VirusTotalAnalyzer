using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UserQuota
{
    [JsonPropertyName("data")]
    public Dictionary<string, QuotaData> Data { get; set; } = new();
}

public sealed class QuotaData
{
    [JsonPropertyName("allowed")]
    public long Allowed { get; set; }

    [JsonPropertyName("used")]
    public long Used { get; set; }
}
