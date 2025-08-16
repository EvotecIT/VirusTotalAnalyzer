using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class CustomUserAgentExample
{
    public static async Task RunAsync()
    {
        using IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY", userAgent: "MyApp/1.0");

        // Use the client here.
        await Task.CompletedTask;
    }
}

