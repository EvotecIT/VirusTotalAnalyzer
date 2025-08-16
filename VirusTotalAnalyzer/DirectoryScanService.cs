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

    private async void OnCreated(object sender, FileSystemEventArgs e)
    {
        if (IsExcluded(e.FullPath))
        {
            return;
        }

        try
        {
            if (_options.ScanDelay > TimeSpan.Zero)
            {
                await Task.Delay(_options.ScanDelay, _cts.Token).ConfigureAwait(false);
            }

            using var stream = new FileStream(e.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            await _client.SubmitFileAsync(stream, Path.GetFileName(e.FullPath), _cts.Token).ConfigureAwait(false);
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
        _watcher.Dispose();
        _cts.Dispose();
    }
}
