using System;

namespace VirusTotalAnalyzer.Examples;

public static class GetUrlIdExample
{
    public static void Run()
    {
        var id = VirusTotalClientExtensions.GetUrlId("https://virustotal.com");
        Console.WriteLine(id);
    }
}
