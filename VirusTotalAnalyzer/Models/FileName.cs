using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileNamesResponse
{
    public List<FileNameInfo> Data { get; set; } = new();

    public Meta? Meta { get; set; }
}

public sealed class FileNameInfo
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public FileNameAttributes Attributes { get; set; } = new();
}

public sealed class FileNameAttributes
{
    public DateTimeOffset Date { get; set; }
}

