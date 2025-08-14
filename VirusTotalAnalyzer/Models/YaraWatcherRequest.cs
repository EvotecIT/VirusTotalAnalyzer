using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraWatcherRequest
{
    public List<YaraWatcher> Data { get; set; } = new();
}

