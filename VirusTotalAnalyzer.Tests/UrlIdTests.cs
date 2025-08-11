using System;
using System.Text;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class UrlIdTests
{
    [Fact]
    public void GetUrlId_CanonicalizesAndEncodes()
    {
        var id = VirusTotalClientExtensions.GetUrlId("HTTP://Virustotal.com");
        const string canonical = "http://virustotal.com/";
        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes(canonical))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        Assert.Equal(expected, id);
    }
}
