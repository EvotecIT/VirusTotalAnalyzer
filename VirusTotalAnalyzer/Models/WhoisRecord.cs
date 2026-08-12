using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents one historical WHOIS snapshot returned by VirusTotal.</summary>
public sealed class WhoisRecord
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public Links Links { get; set; } = new();
    public WhoisRecordAttributes Attributes { get; set; } = new();
}

/// <summary>Contains historical WHOIS metadata and normalized fields.</summary>
public sealed class WhoisRecordAttributes : ExtensibleAttributes
{
    public DateTimeOffset? FirstSeenDate { get; set; }
    public DateTimeOffset? LastUpdated { get; set; }
    public string? RegistrarName { get; set; }
    public string? RegistrantCountry { get; set; }
    public Dictionary<string, string> WhoisMap { get; set; } = new();
}

public sealed class WhoisRecordsResponse
{
    public List<WhoisRecord> Data { get; set; } = new();
    public PaginationMetadata? Meta { get; set; }
}
