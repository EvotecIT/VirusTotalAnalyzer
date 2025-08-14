using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileStringsResponse
{
    public List<string> Data { get; set; } = new();
}