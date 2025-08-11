using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileNamesResponse
{
    [JsonPropertyName("data")]
    public List<FileNameInfo> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public Meta? Meta { get; set; }
}

public sealed class FileNameInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("attributes")]
    public FileNameAttributes Attributes { get; set; } = new();
}

public sealed class FileNameAttributes
{
    [JsonPropertyName("date")]
    public DateTimeOffset Date { get; set; }
}

