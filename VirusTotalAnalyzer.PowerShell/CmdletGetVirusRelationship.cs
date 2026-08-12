using System;
using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves useful typed relationships for VirusTotal network objects.</summary>
/// <para>Returns typed historical WHOIS, DNS resolution, certificate, and related-file objects instead of generic relationship descriptors.</para>
/// <example>
///   <summary>Get historical WHOIS snapshots for a domain.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusRelationship -DomainName 'example.com' -Relationship HistoricalWhois</para>
///   </code>
/// </example>
/// <example>
///   <summary>Find files that communicated with an IP address.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusRelationship -IPAddress '1.1.1.1' -Relationship CommunicatingFiles -Limit 10</para>
///   </code>
/// </example>
/// <seealso href="https://docs.virustotal.com/reference/domain-object-historical-whois" />
[Cmdlet(VerbsCommon.Get, "VirusRelationship", DefaultParameterSetName = "Domain")]
[OutputType(typeof(WhoisRecord), typeof(Resolution), typeof(SslCertificate), typeof(FileReport))]
public sealed class CmdletGetVirusRelationship : VirusTotalCmdlet
{
    /// <summary>Domain whose relationships should be retrieved.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? DomainName { get; set; }

    /// <summary>IP address whose relationships should be retrieved.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "IPAddress", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? IPAddress { get; set; }

    /// <summary>Typed relationship to retrieve.</summary>
    [Parameter(Mandatory = true)]
    public VirusTotalRelationshipType Relationship { get; set; }

    /// <summary>Maximum number of relationship objects to request.</summary>
    [Parameter]
    [ValidateRange(1, 40)]
    public int? Limit { get; set; }

    /// <summary>Cursor returned by a previous relationship request.</summary>
    [Parameter]
    public string? Cursor { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            object? result = ParameterSetName == "Domain"
                ? await GetDomainRelationshipAsync().ConfigureAwait(false)
                : await GetIpAddressRelationshipAsync().ConfigureAwait(false);
            if (result is not null)
                WriteObject(result, enumerateCollection: true);
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, DomainName ?? IPAddress);
        }
    }

    private Task<object?> GetDomainRelationshipAsync()
    {
        var id = DomainName!;
        return Relationship switch
        {
            VirusTotalRelationshipType.HistoricalWhois => Box(ActiveClient.GetDomainHistoricalWhoisAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.Resolutions => Box(ActiveClient.GetDomainResolutionsAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.HistoricalSslCertificates => Box(ActiveClient.GetDomainHistoricalSslCertificatesAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.CommunicatingFiles => Box(ActiveClient.GetDomainCommunicatingFilesAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.ReferrerFiles => Box(ActiveClient.GetDomainReferrerFilesAsync(id, Limit, Cursor, CancelToken)),
            _ => throw new ArgumentOutOfRangeException(nameof(Relationship))
        };
    }

    private Task<object?> GetIpAddressRelationshipAsync()
    {
        var id = IPAddress!;
        return Relationship switch
        {
            VirusTotalRelationshipType.HistoricalWhois => Box(ActiveClient.GetIpAddressHistoricalWhoisAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.Resolutions => Box(ActiveClient.GetIpAddressResolutionsAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.HistoricalSslCertificates => Box(ActiveClient.GetIpAddressHistoricalSslCertificatesAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.CommunicatingFiles => Box(ActiveClient.GetIpAddressCommunicatingFilesAsync(id, Limit, Cursor, CancelToken)),
            VirusTotalRelationshipType.ReferrerFiles => Box(ActiveClient.GetIpAddressReferrerFilesAsync(id, Limit, Cursor, CancelToken)),
            _ => throw new ArgumentOutOfRangeException(nameof(Relationship))
        };
    }

    private static async Task<object?> Box<T>(Task<T> task) => await task.ConfigureAwait(false);
}
