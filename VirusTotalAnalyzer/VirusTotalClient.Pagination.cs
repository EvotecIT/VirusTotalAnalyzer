using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private async Task<PagedResponse<T>?> GetPagedAsync<T>(
        Func<string?, CancellationToken, Task<PagedResponse<T>?>> fetch,
        string? cursor,
        bool fetchAll,
        CancellationToken cancellationToken)
    {
        var allData = new List<T>();
        var seenCursors = new HashSet<string>(StringComparer.Ordinal);
        PagedResponse<T>? page;
        var nextCursor = cursor;
        do
        {
            page = await fetch(nextCursor, cancellationToken).ConfigureAwait(false);
            if (page is null)
            {
                return null;
            }
            allData.AddRange(page.Data);
            nextCursor = page.Meta?.Cursor;
            if (nextCursor is string cursorValue && cursorValue.Length > 0 && !seenCursors.Add(cursorValue))
            {
                throw new InvalidOperationException("VirusTotal returned a repeated pagination cursor.");
            }
        }
        while (fetchAll && !string.IsNullOrEmpty(nextCursor));

        if (fetchAll)
        {
            return new PagedResponse<T>
            {
                Data = allData,
                Meta = page.Meta,
                Links = page.Links
            };
        }

        return page;
    }

    private async IAsyncEnumerable<T> GetPagedAsyncEnumerable<T>(
        Func<string?, CancellationToken, Task<PagedResponse<T>?>> fetch,
        string? cursor,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var nextCursor = cursor;
        var seenCursors = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            var page = await fetch(nextCursor, cancellationToken).ConfigureAwait(false);
            if (page is null)
            {
                yield break;
            }

            foreach (var item in page.Data)
            {
                yield return item;
            }

            nextCursor = page.Meta?.Cursor;
            if (string.IsNullOrEmpty(nextCursor))
            {
                yield break;
            }
            if (!seenCursors.Add(nextCursor!))
            {
                throw new InvalidOperationException("VirusTotal returned a repeated pagination cursor.");
            }
        }
    }
}
