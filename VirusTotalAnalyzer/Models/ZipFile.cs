using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

/// <summary>An asynchronous VirusTotal Intelligence ZIP creation job.</summary>
public sealed class ZipFile
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public ZipFileAttributes Attributes { get; set; } = new();
}

public sealed class ZipFileAttributes : ExtensibleAttributes
{
    public string? Status { get; set; }

    public int? Progress { get; set; }

    public int? FilesOk { get; set; }

    public int? FilesError { get; set; }
}

/// <summary>Request for a ZIP containing files already known to VirusTotal.</summary>
public sealed class CreateZipFileRequest
{
    public CreateZipFileData Data { get; set; } = new();
}

public sealed class CreateZipFileData
{
    public string? Password { get; set; }

    public List<string> Hashes { get; set; } = new();
}
