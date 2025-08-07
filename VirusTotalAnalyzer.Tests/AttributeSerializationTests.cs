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
                    FirstSubmissionDate = 10,
                    Size = 1234,
                    Tags = new List<string> { "tag" },
                    Names = new List<string> { "file.exe" },
                    CrowdSourcedVerdicts = new List<CrowdSourcedVerdict>
                    {
                        new CrowdSourcedVerdict { EngineName = "crowd", Verdict = Verdict.Harmless }
                    },
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
        Assert.Equal(10, roundtrip.Data.Attributes.FirstSubmissionDate);
        Assert.Equal(1234, roundtrip.Data.Attributes.Size);
        Assert.Equal("file.exe", Assert.Single(roundtrip.Data.Attributes.Names));
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("crowd", roundtrip.Data.Attributes.CrowdSourcedVerdicts[0].EngineName);
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
                    FirstSubmissionDate = 70,
                    LastSubmissionDate = 80,
                    Tags = new List<string> { "tag" },
                    CrowdSourcedVerdicts = new List<CrowdSourcedVerdict>
                    {
                        new CrowdSourcedVerdict { EngineName = "crowd", Verdict = Verdict.Malicious }
                    },
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
        Assert.Equal(70, roundtrip.Data.Attributes.FirstSubmissionDate);
        Assert.Equal(80, roundtrip.Data.Attributes.LastSubmissionDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal(1, roundtrip.Data.Attributes.CrowdSourcedVerdicts.Count);
        Assert.Equal(Verdict.Malicious, roundtrip.Data.Attributes.CrowdSourcedVerdicts[0].Verdict);
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

    [Fact]
    public void AnalysisAttributes_Roundtrip()
    {
        var report = new AnalysisReport
        {
            Id = "analysis1",
            Type = ResourceType.Analysis,
            Data = new AnalysisData
            {
                Attributes = new AnalysisAttributes
                {
                    Status = AnalysisStatus.Completed,
                    Date = 123,
                    Stats = new AnalysisStats { Harmless = 1 },
                    Results = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "harmless", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report);
        var roundtrip = JsonSerializer.Deserialize<AnalysisReport>(json);
        Assert.Equal(123, roundtrip!.Data.Attributes.Date);
        Assert.Equal("harmless", roundtrip.Data.Attributes.Results["engine"].Category);
    }
}
