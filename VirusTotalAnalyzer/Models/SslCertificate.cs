using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents a VirusTotal <c>ssl_cert</c> object.</summary>
public sealed class SslCertificate
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public Links Links { get; set; } = new();
    public SslCertificateAttributes Attributes { get; set; } = new();
    public SslCertificateContextAttributes? ContextAttributes { get; set; }
}

/// <summary>Contains the documented fields of a VirusTotal SSL certificate.</summary>
public sealed class SslCertificateAttributes : ExtensibleAttributes
{
    public Dictionary<string, JsonElement> CertSignature { get; set; } = new();
    public Dictionary<string, JsonElement> Extensions { get; set; } = new();
    public DateTimeOffset? FirstSeenDate { get; set; }
    public Dictionary<string, string> Issuer { get; set; } = new();
    public Dictionary<string, JsonElement> PublicKey { get; set; } = new();
    public string? SerialNumber { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public int? Size { get; set; }
    public Dictionary<string, string> Subject { get; set; } = new();
    public string? Thumbprint { get; set; }
    public string? ThumbprintSha256 { get; set; }
    public SslCertificateValidity Validity { get; set; } = new();
    public string? Version { get; set; }
}

public sealed class SslCertificateValidity
{
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }
}

/// <summary>Contains relationship-specific certificate metadata.</summary>
public sealed class SslCertificateContextAttributes
{
    public string? FirstSeenDate { get; set; }

    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
    public int? Port { get; set; }
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
