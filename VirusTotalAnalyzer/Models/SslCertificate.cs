using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class SslCertificate
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public Links Links { get; set; } = new();
    public SslCertificateData Data { get; set; } = new();
}

public sealed class SslCertificateData
{
    public SslCertificateAttributes Attributes { get; set; } = new();
}

public sealed class SslCertificateAttributes
{
    public string? Sha256 { get; set; }
    public string? Subject { get; set; }
    public string? Issuer { get; set; }

    [JsonPropertyName("validity_not_before")]
    public DateTimeOffset? ValidityNotBefore { get; set; }

    [JsonPropertyName("validity_not_after")]
    public DateTimeOffset? ValidityNotAfter { get; set; }
}

public sealed class SslCertificateResponse
{
    public SslCertificate Data { get; set; } = new();
}

public sealed class SslCertificatesResponse
{
    public List<SslCertificate> Data { get; set; } = new();
    public PaginationMetadata? Meta { get; set; }
}

