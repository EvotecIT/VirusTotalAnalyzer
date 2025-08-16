using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

[Collection("DirectoryScan")]
public class DirectoryScanServiceTests
{
    private static HttpResponseMessage CreateResponse()
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}", Encoding.UTF8, "application/json")
        };

    private static Task WriteFileAsync(string path, string contents)
    {
#if NETFRAMEWORK
        File.WriteAllText(path, contents);
        return Task.CompletedTask;
#else
        return File.WriteAllTextAsync(path, contents);
#endif
    }

    private static void DeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        for (var i = 0; i < 5; i++)
        {
            try
            {
                Directory.Delete(path, true);
                return;
            }
            catch (IOException) when (i < 4)
            {
                Thread.Sleep(100);
            }
            catch (UnauthorizedAccessException) when (i < 4)
            {
                Thread.Sleep(100);
            }
        }

        Directory.Delete(path, true);
    }

    [Fact]
    public async Task Submits_New_Files()
    {
        var tcs = new TaskCompletionSource<HttpRequestMessage>();
        var handler = new CallbackHandler(req => tcs.TrySetResult(req));
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") };
        var client = new VirusTotalClient(httpClient);

        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        try
        {
            var options = new DirectoryScanOptions { DirectoryPath = dir };
            using var service = new DirectoryScanService(client, options);

            var filePath = Path.Combine(dir, "test.bin");
            await WriteFileAsync(filePath, "data");

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(tcs.Task, completed);
            var request = await tcs.Task;
            Assert.Equal("/api/v3/files", request.RequestUri!.AbsolutePath);
        }
        finally
        {
            DeleteDirectory(dir);
        }
    }

    [Fact]
    public async Task Excludes_Configured_Patterns()
    {
        var tcs = new TaskCompletionSource<HttpRequestMessage>();
        var handler = new CallbackHandler(req => tcs.TrySetResult(req));
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") };
        var client = new VirusTotalClient(httpClient);

        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        try
        {
            var options = new DirectoryScanOptions
            {
                DirectoryPath = dir,
                ExclusionFilters = new[] { "*.tmp" }
            };
            using var service = new DirectoryScanService(client, options);

            var excluded = Path.Combine(dir, "skip.tmp");
            await WriteFileAsync(excluded, "data");
            await Task.Delay(300); // wait to ensure no submission
            Assert.False(tcs.Task.IsCompleted);

            var included = Path.Combine(dir, "go.bin");
            await WriteFileAsync(included, "data");

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(tcs.Task, completed);
            var request = await tcs.Task;
            Assert.Equal("/api/v3/files", request.RequestUri!.AbsolutePath);
        }
        finally
        {
            DeleteDirectory(dir);
        }
    }

    [Fact]
    public async Task Waits_For_Scan_Delay()
    {
        var tcs = new TaskCompletionSource<DateTime>();
        var handler = new CallbackHandler(_ => tcs.TrySetResult(DateTime.UtcNow));
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") };
        var client = new VirusTotalClient(httpClient);

        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        try
        {
            var delay = TimeSpan.FromMilliseconds(300);
            var filePath = Path.Combine(dir, "delay.bin");
            await WriteFileAsync(filePath, "data");

            var options = new DirectoryScanOptions { DirectoryPath = dir, ScanDelay = delay };
            using var service = new DirectoryScanService(client, options);

            var start = DateTime.UtcNow;
            await service.ProcessFileAsync(filePath);

            var time = await tcs.Task;
            var elapsed = time - start;
            Assert.True(elapsed >= delay - TimeSpan.FromMilliseconds(50), $"elapsed {elapsed} is less than delay {delay}");
        }
        finally
        {
            DeleteDirectory(dir);
        }
    }

    private sealed class CallbackHandler : HttpMessageHandler
    {
        private readonly Action<HttpRequestMessage> _callback;

        public CallbackHandler(Action<HttpRequestMessage> callback) => _callback = callback;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            _callback(request);
            return Task.FromResult(CreateResponse());
        }
    }
}

[CollectionDefinition("DirectoryScan", DisableParallelization = true)]
public sealed class DirectoryScanCollection : ICollectionFixture<object>
{
}
