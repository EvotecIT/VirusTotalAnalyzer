using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MonitorStatisticsTests
{
    [Fact]
    public async Task GetMonitorStatisticsAsync_DeserializesHistoricalAndRealtimeStatistics()
    {
        const string json = """
            {
              "data": [{
                "id": "owner-day-2024-07-01",
                "type": "monitor_statistics",
                "attributes": {
                  "date": 1719792000,
                  "items_detected_count": 28,
                  "increasing_detections_count": 6,
                  "owner_id": "owner",
                  "period": "day",
                  "storage_bytes_count": 166709820,
                  "storage_files_count": 34,
                  "top_engines": [{ "count": 20, "engine": "Engine" }]
                }
              }],
              "meta": {
                "cursor": "next",
                "realtime": {
                  "items_detected_count": 28,
                  "new_detections_count": 3,
                  "solved_detections_count": 2
                }
              }
            }
            """;
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        using var client = new VirusTotalClient(httpClient);

        var response = await client.GetMonitorStatisticsAsync(10, "start");

        var period = Assert.Single(response!.Data);
        Assert.Equal(28, period.Attributes.ItemsDetectedCount);
        Assert.Equal("Engine", Assert.Single(period.Attributes.TopEngines).Engine);
        Assert.Equal(3, response.Meta.Realtime.NewDetectionsCount);
        Assert.Equal("next", response.Meta.Cursor);
        Assert.Equal("?limit=10&cursor=start", handler.Request!.RequestUri!.Query);
    }
}
