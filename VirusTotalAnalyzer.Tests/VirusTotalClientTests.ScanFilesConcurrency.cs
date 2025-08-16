using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task ScanFilesAsync_RespectsMaxConcurrency()
    {
        var handler = new MaxConcurrencyHandler();
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var files = new List<string>();
        for (int i = 0; i < 5; i++)
        {
            var path = System.IO.Path.GetTempFileName();
#if NETFRAMEWORK
            System.IO.File.WriteAllText(path, "demo");
#else
            await System.IO.File.WriteAllTextAsync(path, "demo");
#endif
            files.Add(path);
        }

        try
        {
            var reports = await client.ScanFilesAsync(files, maxConcurrency: 2);
            Assert.Equal(files.Count, reports.Count);
            Assert.True(handler.MaxConcurrency <= 2);
        }
        finally
        {
            foreach (var file in files)
            {
                System.IO.File.Delete(file);
            }
        }
    }

    private sealed class MaxConcurrencyHandler : HttpMessageHandler
    {
        private int _current;
        public int MaxConcurrency { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var started = Interlocked.Increment(ref _current);
            UpdateMax(started);
            try
            {
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}")
                };
            }
            finally
            {
                Interlocked.Decrement(ref _current);
            }
        }

        private void UpdateMax(int current)
        {
            int initial;
            do
            {
                initial = MaxConcurrency;
                if (current <= initial)
                {
                    return;
                }
            }
            while (Interlocked.CompareExchange(ref MaxConcurrency, current, initial) != initial);
        }
    }
}
