using System;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileReportExample
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
        var report = await client.GetFileReportAsync("44d88612fea8a8f36de82e1278abb02f");
        Console.WriteLine($"Sample file md5: {report?.Data.Attributes.Md5}, size: {report?.Data.Attributes.Size}");
    }
}
