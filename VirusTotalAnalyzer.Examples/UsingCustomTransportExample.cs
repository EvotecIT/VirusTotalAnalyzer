using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class UsingCustomTransportExample
{
    public static async Task RunAsync()
    {
        var apiHandler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            // Configure proxy, client certificate, and DNS behavior here.
        };
        var downloadHandler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            // Mirror required transport settings without adding authentication headers.
        };
        using IVirusTotalClient client = new VirusTotalClient(
            "YOUR_API_KEY",
            apiHandler,
            downloadHandler,
            disposeHandlers: true);

        // Use the client here.
        await Task.CompletedTask;
    }
}
