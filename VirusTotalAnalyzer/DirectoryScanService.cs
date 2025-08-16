using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer;

/// <summary>
/// Watches a directory and submits newly created files to VirusTotal.
/// </summary>
public sealed class DirectoryScanService : IDisposable
{
    private readonly VirusTotalClient _client;
    private readonly DirectoryScanOptions _options;
    private readonly FileSystemWatcher _watcher;
    private readonly CancellationTokenSource _cts = new();
    private readonly System.Collections.Generic.List<Task> _running = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryScanService"/> class.
    /// </summary>
    /// <param name="client">The <see cref="VirusTotalClient"/> used for submissions.</param>
    /// <param name="options">Configuration options.</param>
    public DirectoryScanService(VirusTotalClient client, DirectoryScanOptions options)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrEmpty(options.DirectoryPath))
        {
            throw new ArgumentException("Directory path must be specified.", nameof(options));
        }
        _watcher = new FileSystemWatcher(options.DirectoryPath)
        {
            EnableRaisingEvents = true,
            IncludeSubdirectories = false
        };
        _watcher.Created += OnCreated;
    }

    private void OnCreated(object sender, FileSystemEventArgs e)
    {
        if (IsExcluded(e.FullPath))
        {
            return;
        }

        var task = ProcessFileAsync(e.FullPath);
        lock (_running)
        {
            _running.Add(task);
        }
        _ = task.ContinueWith(static (t, state) =>
        {
            var list = (System.Collections.Generic.List<Task>)state!;
            lock (list)
            {
                list.Remove(t);
            }
        }, _running, TaskScheduler.Default);
    }

    internal async Task ProcessFileAsync(string path)
    {
        try
        {
            if (_options.ScanDelay > TimeSpan.Zero)
            {
                await Task.Delay(_options.ScanDelay, _cts.Token).ConfigureAwait(false);
            }

            for (var i = 0; i < 5; i++)
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    await _client.SubmitFileAsync(stream, Path.GetFileName(path), _cts.Token).ConfigureAwait(false);
                    break;
                }
                catch (IOException) when (i < 4)
                {
                    await Task.Delay(100, _cts.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
            // Swallow exceptions from scanning individual files.
        }
    }

    private bool IsExcluded(string path)
    {
        var name = Path.GetFileName(path);
        return _options.ExclusionFilters.Any(p => WildcardMatch(name, p));
    }

    private static bool WildcardMatch(string input, string pattern)
    {
        var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
#if NETFRAMEWORK
        return Regex.IsMatch(input, regex, RegexOptions.IgnoreCase);
#else
        return Regex.IsMatch(input, regex, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
#endif
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _cts.Cancel();
        _watcher.Created -= OnCreated;
        _watcher.EnableRaisingEvents = false;
        _watcher.Dispose();
        Task[] tasks;
        lock (_running)
        {
            tasks = _running.ToArray();
        }
        try
        {
            Task.WhenAll(tasks).GetAwaiter().GetResult();
        }
        catch
        {
            // Ignore any exceptions from outstanding tasks during disposal.
        }
        _cts.Dispose();
    }
}
