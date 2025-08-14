using System;

namespace VirusTotalAnalyzer.Models;

public sealed class RetrohuntJobRequest
{
    public RetrohuntJobRequestData Data { get; set; } = new();
}

public sealed class RetrohuntJobRequestData
{
    public string Type { get; set; } = "retrohunt_job";

    public RetrohuntJobRequestAttributes Attributes { get; set; } = new();
}

public sealed class RetrohuntJobRequestAttributes
{
    public string Rules { get; set; } = string.Empty;

    public string? Comment { get; set; }

    public DateTimeOffset? From { get; set; }

    public DateTimeOffset? To { get; set; }
}

