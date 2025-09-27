using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    public async Task<PagedResponse<User>?> GetGraphCollaboratorsAsync(string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new StringBuilder($"graphs/{Uri.EscapeDataString(id)}/collaborators");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<User>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RelationshipResponse?> AddGraphCollaboratorsAsync(string id, AddCollaboratorsRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"graphs/{Uri.EscapeDataString(id)}/collaborators", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<RelationshipResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteGraphCollaboratorAsync(string graphId, string username, CancellationToken cancellationToken = default)
    {
        ValidateId(graphId, nameof(graphId));
        ValidateId(username, nameof(username));
        using var response = await _httpClient.DeleteAsync($"graphs/{Uri.EscapeDataString(graphId)}/collaborators/{Uri.EscapeDataString(username)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }
}

