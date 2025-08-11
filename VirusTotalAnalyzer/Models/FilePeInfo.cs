using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FilePeInfo
{
    [JsonPropertyName("data")]
    public PeInfoData Data { get; set; } = new();
}

public sealed class PeInfoData
{
    [JsonPropertyName("attributes")]
    public PeInfoAttributes Attributes { get; set; } = new();
}

public sealed class PeInfoAttributes
{
    [JsonPropertyName("imphash")]
    public string? Imphash { get; set; }

    [JsonPropertyName("machine_type")]
    public string? MachineType { get; set; }

    [JsonPropertyName("sections")]
    public List<PeSection> Sections { get; set; } = new();
}

public sealed class PeSection
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}
