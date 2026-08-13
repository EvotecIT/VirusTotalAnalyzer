using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    /// <summary>Gets users and groups with the selected access level on a graph.</summary>
    public Task<PagedResponse<GraphPrincipal>?> GetGraphPermissionsAsync(
        string graphId,
        GraphPermission permission,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(graphId, nameof(graphId));
        return GetPageAsync<GraphPrincipal>(
            $"graphs/{Uri.EscapeDataString(graphId)}/relationships/{GetGraphPermissionPath(permission)}",
            limit,
            cursor,
            cancellationToken);
    }

    /// <summary>Grants viewer or editor access to users or groups.</summary>
    public Task<RelationshipResponse?> GrantGraphPermissionAsync(
        string graphId,
        GraphPermission permission,
        GraphPermissionRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateId(graphId, nameof(graphId));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        request.Validate();
        return SendJsonResponseAsync<GraphPermissionRequest, RelationshipResponse>(
            HttpMethod.Post,
            $"graphs/{Uri.EscapeDataString(graphId)}/relationships/{GetGraphPermissionPath(permission)}",
            request,
            cancellationToken);
    }

    /// <summary>Revokes viewer or editor access from one user or group.</summary>
    public async Task RevokeGraphPermissionAsync(
        string graphId,
        GraphPermission permission,
        string principalId,
        CancellationToken cancellationToken = default)
    {
        ValidateId(graphId, nameof(graphId));
        ValidateId(principalId, nameof(principalId));
        ThrowIfDisposed();
        using var response = await _httpClient.DeleteAsync(
            $"graphs/{Uri.EscapeDataString(graphId)}/relationships/{GetGraphPermissionPath(permission)}/{Uri.EscapeDataString(principalId)}",
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    private static string GetGraphPermissionPath(GraphPermission permission)
        => permission switch
        {
            GraphPermission.Viewer => "viewers",
            GraphPermission.Editor => "editors",
            _ => throw new ArgumentOutOfRangeException(nameof(permission))
        };
}
