using System;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class DirectoryScanServiceExample
{
    public static async Task RunAsync()
    {
        var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
        if (string.IsNullOrEmpty(apiKey))
        {
            Console.WriteLine("VT_API_KEY environment variable not set.");
            return;
        }

        using var client = VirusTotalClient.Create(apiKey);
        var options = new DirectoryScanOptions
        {
            DirectoryPath = "/path/to/watch",
            ExclusionFilters = new[] { "*.tmp", "*.log" },
            ScanDelay = TimeSpan.FromSeconds(2)
        };
        using var service = new DirectoryScanService(client, options);

        Console.WriteLine($"Watching {options.DirectoryPath}. Press ENTER to exit.");
        await Task.Run(() => Console.ReadLine());
    }
}
