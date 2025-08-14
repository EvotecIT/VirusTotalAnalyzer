using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class UserQuota
{
    public Dictionary<string, QuotaData> Data { get; set; } = new();
}

public sealed class QuotaData
{
    public long Allowed { get; set; }

    public long Used { get; set; }
}