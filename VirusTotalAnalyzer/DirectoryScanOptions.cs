using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer;

/// <summary>
/// Options for <see cref="DirectoryScanService"/>.
/// </summary>
public sealed class DirectoryScanOptions
{
    /// <summary>
    /// Gets or sets the directory path to monitor.
    /// </summary>
    public string DirectoryPath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets wildcard patterns for files that should be excluded from scanning.
    /// </summary>
    public IReadOnlyCollection<string> ExclusionFilters { get; set; }
        = Array.Empty<string>();

    /// <summary>
    /// Gets or sets the delay before scanning a new file.
    /// </summary>
    public TimeSpan ScanDelay { get; set; } = TimeSpan.Zero;
}
