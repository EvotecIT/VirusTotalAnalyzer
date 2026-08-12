using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public sealed class VirusTotalClientWhoisTests
{
    [Theory]
    [InlineData(true, "/api/v3/domains/example.com/historical_whois")]
    [InlineData(false, "/api/v3/ip_addresses/1.1.1.1/historical_whois")]
    public async Task HistoricalWhois_UsesTypedRouteAndDeserializesMap(bool domain, string expectedPath)
    {
        var json = "{\"data\":[{\"id\":\"w1\",\"type\":\"whois\",\"attributes\":{\"first_seen_date\":100,\"last_updated\":200,\"registrar_name\":\"Example Registrar\",\"whois_map\":{\"Domain Name\":\"EXAMPLE.COM\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        using var client = new VirusTotalClient(new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        });

        var records = domain
            ? await client.GetDomainHistoricalWhoisAsync("example.com")
            : await client.GetIpAddressHistoricalWhoisAsync("1.1.1.1");

        Assert.Equal(expectedPath, handler.Request!.RequestUri!.AbsolutePath);
        var record = Assert.Single(records!);
        Assert.Equal(ResourceType.Whois, record.Type);
        Assert.Equal("Example Registrar", record.Attributes.RegistrarName);
        Assert.Equal("EXAMPLE.COM", record.Attributes.WhoisMap["Domain Name"]);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(100), record.Attributes.FirstSeenDate);
    }
}
