using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class PagedResponse<T>
{
    public List<T> Data { get; set; } = new();

    public Meta? Meta { get; set; }

    public string? NextCursor => Meta?.Cursor;
}