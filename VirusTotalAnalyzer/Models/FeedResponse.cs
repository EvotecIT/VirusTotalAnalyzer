using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FeedResponse
{
    public List<FeedItem> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class FeedItem
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
}