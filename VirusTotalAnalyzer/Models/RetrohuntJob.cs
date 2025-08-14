using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class RetrohuntJob
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public RetrohuntJobData Data { get; set; } = new();
}

public sealed class RetrohuntJobData
{
    public RetrohuntJobAttributes Attributes { get; set; } = new();
}

public sealed class RetrohuntJobAttributes
{
    public string Status { get; set; } = string.Empty;
}

public sealed class RetrohuntJobResponse
{
    public RetrohuntJob? Data { get; set; }
}

public sealed class RetrohuntJobsResponse
{
    public List<RetrohuntJob> Data { get; set; } = new();

    public Meta? Meta { get; set; }
}