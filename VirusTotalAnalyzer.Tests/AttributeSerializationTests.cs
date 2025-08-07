using System.Collections.Generic;
using System.Text.Json;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class AttributeSerializationTests
{
    [Fact]
    public void FileAttributes_Roundtrip()
    {
        var report = new FileReport
        {
            Id = "file1",
            Type = ResourceType.File,
            Data = new FileData
            {
                Attributes = new FileAttributes
                {
                    Md5 = "md5",
                    Reputation = 1,
                    CreationDate = 42,
                    Tags = new List<string> { "tag" },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "harmless", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report);
        var roundtrip = JsonSerializer.Deserialize<FileReport>(json);
        Assert.Equal(42, roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("harmless", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
    }

    [Fact]
    public void UrlAttributes_Roundtrip()
    {
        var report = new UrlReport
        {
            Id = "url1",
            Type = ResourceType.Url,
            Data = new UrlData
            {
                Attributes = new UrlAttributes
                {
                    Url = "https://example.com",
                    Reputation = 2,
                    CreationDate = 84,
                    Tags = new List<string> { "tag" },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "malicious", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report);
        var roundtrip = JsonSerializer.Deserialize<UrlReport>(json);
        Assert.Equal(84, roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("malicious", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
    }

    [Fact]
    public void DomainAttributes_Roundtrip()
    {
        var report = new DomainReport
        {
            Id = "domain1",
            Type = ResourceType.Domain,
            Data = new DomainData
            {
                Attributes = new DomainAttributes
                {
                    Domain = "example.com",
                    Reputation = 3,
                    CreationDate = 21,
                    Tags = new List<string> { "tag" },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "suspicious", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report);
        var roundtrip = JsonSerializer.Deserialize<DomainReport>(json);
        Assert.Equal(21, roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("suspicious", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
    }

    [Fact]
    public void IpAddressAttributes_Roundtrip()
    {
        var report = new IpAddressReport
        {
            Id = "ip1",
            Type = ResourceType.IpAddress,
            Data = new IpAddressData
            {
                Attributes = new IpAddressAttributes
                {
                    IpAddress = "1.2.3.4",
                    Reputation = 4,
                    CreationDate = 63,
                    Tags = new List<string> { "tag" },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "undetected", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report);
        var roundtrip = JsonSerializer.Deserialize<IpAddressReport>(json);
        Assert.Equal(63, roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("undetected", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
    }
}
