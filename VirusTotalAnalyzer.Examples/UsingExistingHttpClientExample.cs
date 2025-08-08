using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class UsingExistingHttpClientExample
{
    public static async Task RunAsync()
    {
        var httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", "YOUR_API_KEY");

        using var client = new VirusTotalClient(httpClient, disposeClient: true);

        // Use the client here.
        await Task.CompletedTask;
    }
}
