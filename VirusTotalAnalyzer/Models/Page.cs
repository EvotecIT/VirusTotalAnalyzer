using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Page<T>
{
    public Page(List<T> data, string? nextCursor)
    {
        Data = data;
        NextCursor = nextCursor;
    }

    public IReadOnlyList<T> Data { get; }

    public string? NextCursor { get; }
}

