using System;
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

        var client = VirusTotalClient.Create(apiKey);
        var analysis = await client.SubmitUrlAsync("https://example.com", AnalysisType.Url);
        Console.WriteLine($"Submission status: {analysis?.Data.Attributes.Status}");
    }
}
