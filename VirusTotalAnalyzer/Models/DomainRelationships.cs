using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainSubdomainsResponse
{
    public List<DomainSummary> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class DomainSiblingsResponse
{
    public List<DomainSummary> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class DomainUrlsResponse
{
    public List<UrlSummary> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

