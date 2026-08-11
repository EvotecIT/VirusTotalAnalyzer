using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public partial interface IVirusTotalClient
{
    Task<MonitorUploadResult> UploadMonitorFileAsync(string filePath, MonitorUploadOptions options, CancellationToken cancellationToken = default);

    Task<MonitorUploadResult> UploadMonitorFileAsync(Stream stream, string fileName, MonitorUploadOptions options, CancellationToken cancellationToken = default);

    Task<MonitorItem?> CreateMonitorFolderAsync(string path, CancellationToken cancellationToken = default);

    Task<MonitorItem?> ConfigureMonitorItemAsync(string id, string details, CancellationToken cancellationToken = default);

    Task<MonitorItem?> GetMonitorItemAsync(string id, CancellationToken cancellationToken = default);

    Task<PagedResponse<MonitorItem>?> ListMonitorItemsAsync(string? filter = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    Task<PagedResponse<MonitorItem>?> ListMonitorItemsAsync(MonitorItemFilter filter, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    IAsyncEnumerable<MonitorItem> EnumerateMonitorItemsAsync(string? filter = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    IAsyncEnumerable<MonitorItem> EnumerateMonitorItemsAsync(MonitorItemFilter filter, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    Task<PagedResponse<MonitorAnalysis>?> GetMonitorItemAnalysesAsync(string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    Task<PagedResponse<MonitorItemComment>?> GetMonitorItemCommentsAsync(string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    Task<PagedResponse<MonitorEvent>?> ListMonitorEventsAsync(string? filter = null, string? cursor = null, string? jobId = null, CancellationToken cancellationToken = default);

    IAsyncEnumerable<MonitorEvent> EnumerateMonitorEventsAsync(string? filter = null, string? cursor = null, string? jobId = null, CancellationToken cancellationToken = default);

    Task<MonitorStatisticsResponse?> GetMonitorStatisticsAsync(int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    Task<Stream> DownloadMonitorItemAsync(string id, CancellationToken cancellationToken = default);

    Task<Uri?> GetMonitorItemDownloadUrlAsync(string id, CancellationToken cancellationToken = default);

    Task DeleteMonitorItemAsync(string id, CancellationToken cancellationToken = default);
}
