using System.Collections.Generic;
using System.Text.Json;

namespace VirusTotalAnalyzer.Models;

public sealed class IocStreamResponse
{
    public List<IocStreamItem> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class IocStreamItem
{
    public string Type { get; set; } = string.Empty;

    public string Id { get; set; } = string.Empty;

    public Dictionary<string, JsonElement>? Attributes { get; set; }
}