using System;
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
        var options = new JsonSerializerOptions();
        options.Converters.Add(new UnixTimestampConverter());

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
                    CreationDate = DateTimeOffset.FromUnixTimeSeconds(42),
                    Tags = new List<string> { "tag" },
                    Size = 100,
                    FirstSubmissionDate = DateTimeOffset.FromUnixTimeSeconds(10),
                    CrowdsourcedVerdicts =
                    {
                        new CrowdsourcedVerdict { Source = "cs", Verdict = Verdict.Harmless, Timestamp = DateTimeOffset.FromUnixTimeSeconds(1) }
                    },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "harmless", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report, options);
        var roundtrip = JsonSerializer.Deserialize<FileReport>(json, options);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(42), roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("harmless", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
        Assert.Equal(100, roundtrip.Data.Attributes.Size);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(10), roundtrip.Data.Attributes.FirstSubmissionDate);
        Assert.Equal(Verdict.Harmless, roundtrip.Data.Attributes.CrowdsourcedVerdicts[0].Verdict);
    }

    [Fact]
    public void UrlAttributes_Roundtrip()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new UnixTimestampConverter());

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
                    CreationDate = DateTimeOffset.FromUnixTimeSeconds(84),
                    Tags = new List<string> { "tag" },
                    FirstSubmissionDate = DateTimeOffset.FromUnixTimeSeconds(11),
                    CrowdsourcedVerdicts =
                    {
                        new CrowdsourcedVerdict { Source = "cs", Verdict = Verdict.Malicious, Timestamp = DateTimeOffset.FromUnixTimeSeconds(2) }
                    },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "malicious", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report, options);
        var roundtrip = JsonSerializer.Deserialize<UrlReport>(json, options);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(84), roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("malicious", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(11), roundtrip.Data.Attributes.FirstSubmissionDate);
        Assert.Equal(Verdict.Malicious, roundtrip.Data.Attributes.CrowdsourcedVerdicts[0].Verdict);
    }

    [Fact]
    public void AnalysisAttributes_Roundtrip()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new UnixTimestampConverter());

        var report = new AnalysisReport
        {
            Id = "an1",
            Type = ResourceType.Analysis,
            Data = new AnalysisData
            {
                Attributes = new AnalysisAttributes
                {
                    Status = AnalysisStatus.Completed,
                    Date = DateTimeOffset.FromUnixTimeSeconds(5),
                    Results = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "harmless", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report, options);
        var roundtrip = JsonSerializer.Deserialize<AnalysisReport>(json, options);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(5), roundtrip!.Data.Attributes.Date);
        Assert.Equal("harmless", roundtrip.Data.Attributes.Results["engine"].Category);
    }

    [Fact]
    public void DomainAttributes_Roundtrip()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new UnixTimestampConverter());

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
                    CreationDate = DateTimeOffset.FromUnixTimeSeconds(21),
                    Tags = new List<string> { "tag" },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "suspicious", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report, options);
        var roundtrip = JsonSerializer.Deserialize<DomainReport>(json, options);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(21), roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("suspicious", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
    }

    [Fact]
    public void IpAddressAttributes_Roundtrip()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new UnixTimestampConverter());

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
                    CreationDate = DateTimeOffset.FromUnixTimeSeconds(63),
                    Tags = new List<string> { "tag" },
                    LastAnalysisResults = new Dictionary<string, AnalysisResult>
                    {
                        ["engine"] = new AnalysisResult { Category = "undetected", EngineName = "engine" }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(report, options);
        var roundtrip = JsonSerializer.Deserialize<IpAddressReport>(json, options);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(63), roundtrip!.Data.Attributes.CreationDate);
        Assert.Equal("tag", Assert.Single(roundtrip.Data.Attributes.Tags));
        Assert.Equal("undetected", roundtrip.Data.Attributes.LastAnalysisResults["engine"].Category);
    }
}
