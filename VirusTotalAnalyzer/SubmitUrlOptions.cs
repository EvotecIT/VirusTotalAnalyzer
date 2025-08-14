using System;

namespace VirusTotalAnalyzer;

/// <summary>
/// Options for <see cref="VirusTotalClient.SubmitUrlAsync(string, SubmitUrlOptions?, System.Threading.CancellationToken)"/>.
/// </summary>
public sealed class SubmitUrlOptions
{
    /// <summary>
    /// When set to <see langword="true"/>, the request will block until the analysis completes.
    /// </summary>
    public bool WaitForCompletion { get; set; }

    /// <summary>
    /// Controls whether the URL should be analyzed after submission. If <see langword="null"/>,
    /// the API default is used.
    /// </summary>
    public bool? Analyze { get; set; }
}
