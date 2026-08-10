using System;

namespace VirusTotalAnalyzer.Models;

/// <summary>Controls a VirusTotal Monitor file upload.</summary>
public sealed class MonitorUploadOptions
{
    public string? Path { get; set; }

    public string? ExistingItemId { get; set; }

    public string? Details { get; set; }

    public bool VerifySha256 { get; set; } = true;

    public TimeSpan VerificationTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(2);
}

public enum MonitorUploadVerificationStatus
{
    NotRequested,
    Pending,
    Verified
}

public enum MonitorUploadDisposition
{
    Created,
    Replaced
}

/// <summary>Describes an accepted Monitor upload and its optional hash verification.</summary>
public sealed class MonitorUploadResult
{
    public MonitorItem Item { get; set; } = new();

    public string LocalSha256 { get; set; } = string.Empty;

    public string? RemoteSha256 { get; set; }

    public string? DestinationPath { get; set; }

    public bool UsedExistingItemId { get; set; }

    public bool UsedLargeFileUploadUrl { get; set; }

    public MonitorUploadVerificationStatus VerificationStatus { get; set; }

    public MonitorUploadDisposition Disposition => UsedExistingItemId
        ? MonitorUploadDisposition.Replaced
        : MonitorUploadDisposition.Created;

    public string MonitorId => Item.Id;

    public string RemotePath => Item.Attributes.Path;

    public int? CurrentDetectionCount => Item.Attributes.LastDetectionsCount;
}
