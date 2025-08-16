using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class MultipartFormDataBuilderExample
{
    public static async Task RunAsync()
    {
        var path = "sample.txt";
        if (!File.Exists(path))
        {
            Console.WriteLine($"File not found: {path}");
            return;
        }
#if NET472
        using var stream = File.OpenRead(path);
#else
        await using var stream = File.OpenRead(path);
#endif
        var builder = new MultipartFormDataBuilder(stream, Path.GetFileName(path))
            .WithFormField("field1", "value1")
            .WithFormField("field2", "value2");
        using var content = builder.Build();

        using var client = new HttpClient();
        var response = await client.PostAsync("https://example.com/upload", content);
        Console.WriteLine(response.StatusCode);
    }
}
