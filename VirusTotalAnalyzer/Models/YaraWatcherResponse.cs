using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraWatcherResponse
{
    public List<YaraWatcher> Data { get; set; } = new();
}

