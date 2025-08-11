using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UserPrivileges
{
    [JsonPropertyName("data")]
    public Dictionary<string, PrivilegeData> Data { get; set; } = new();
}

public sealed class PrivilegeData
{
    [JsonPropertyName("allowed")]
    public bool Allowed { get; set; }
}
