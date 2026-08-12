using System.Collections.Generic;
using System.Text.Json;

namespace VirusTotalAnalyzer.Models;

public sealed class SearchResponse
{
    public List<SearchResult> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }

    public Links? Links { get; set; }
}

public sealed class SearchResult
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public Dictionary<string, JsonElement> Attributes { get; set; } = new();
}
