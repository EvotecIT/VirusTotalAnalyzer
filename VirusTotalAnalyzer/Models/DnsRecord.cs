using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DnsRecord
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public DnsRecordData Data { get; set; } = new();
}

public sealed class DnsRecordData
{
    public DnsRecordAttributes Attributes { get; set; } = new();
}

public sealed class DnsRecordAttributes
{
    [JsonPropertyName("type")]
    public string? RecordType { get; set; }

    [JsonPropertyName("value")]
    public string? Value { get; set; }

    [JsonPropertyName("ttl")]
    public int? Ttl { get; set; }
}

public sealed class DnsRecordsResponse
{
    [JsonPropertyName("data")]
    public List<DnsRecord> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}
