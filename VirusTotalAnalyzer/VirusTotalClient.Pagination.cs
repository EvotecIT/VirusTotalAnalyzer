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
        }
        while (fetchAll && !string.IsNullOrEmpty(nextCursor));

        if (fetchAll)
        {
            return new PagedResponse<T>
            {
                Data = allData,
                Meta = page.Meta
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
        }
    }
}
