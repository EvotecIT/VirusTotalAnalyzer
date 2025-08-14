using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Resolution
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public ResolutionData Data { get; set; } = new();
}

public sealed class ResolutionData
{
    public ResolutionAttributes Attributes { get; set; } = new();
}

public sealed class ResolutionAttributes
{
    public DateTimeOffset Date { get; set; }

    public string? HostName { get; set; }

    public string? IpAddress { get; set; }
}

public sealed class ResolutionsResponse
{
    public List<Resolution> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}