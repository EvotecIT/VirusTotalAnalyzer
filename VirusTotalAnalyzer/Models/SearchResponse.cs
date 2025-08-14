using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class SearchResponse
{
    public List<SearchResult> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class SearchResult
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
}