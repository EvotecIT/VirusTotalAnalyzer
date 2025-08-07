using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class SubmitUrlExample
{
    public static async Task RunAsync()
    {
        var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Console.WriteLine("VT_API_KEY environment variable is not set.");
            return;
        }

        using var httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);

        var client = new VirusTotalClient(httpClient);
        var analysis = await client.SubmitUrlAsync("https://example.com", AnalysisType.Url);
        Console.WriteLine($"Submission status: {analysis?.Data.Attributes.Status}");
    }
}
