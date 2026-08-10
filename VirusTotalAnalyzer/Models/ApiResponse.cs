namespace VirusTotalAnalyzer.Models;

/// <summary>
/// Represents the standard successful VirusTotal API v3 response envelope.
/// </summary>
/// <typeparam name="T">Type stored in the response's <c>data</c> property.</typeparam>
public sealed class ApiResponse<T>
{
    /// <summary>Gets or sets the response data.</summary>
    public T? Data { get; set; }
}
