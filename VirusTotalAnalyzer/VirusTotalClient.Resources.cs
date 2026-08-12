using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    public Task<PagedResponse<Graph>?> ListGraphsAsync(int? limit = null, string? cursor = null, bool fetchAll = false, CancellationToken cancellationToken = default)
        => GetPagedAsync<Graph>(async (c, token) =>
        {
            var path = new StringBuilder("graphs");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<Graph>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);

    public async Task<Graph?> GetGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"graphs/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<Graph>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Graph?> CreateGraphAsync(CreateGraphRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("graphs", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<Graph>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Graph?> UpdateGraphAsync(string id, UpdateGraphRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"graphs/{Uri.EscapeDataString(id)}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<Graph>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"graphs/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public Task<CommentsResponse?> GetGraphCommentsAsync(string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
        => GetCommentsAsync(ResourceType.Graph, id, limit, cursor, cancellationToken);

    public Task<Comment?> AddGraphCommentAsync(string id, string text, CancellationToken cancellationToken = default)
        => CreateCommentAsync(ResourceType.Graph, id, text, cancellationToken);

    public Task<Comment?> AddGraphCommentAsync(string id, CreateCommentRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        return CreateCommentAsync(ResourceType.Graph, id, request, cancellationToken);
    }

    public Task<PagedResponse<Collection>?> ListCollectionsAsync(int? limit = null, string? cursor = null, bool fetchAll = false, CancellationToken cancellationToken = default)
        => GetPagedAsync<Collection>(async (c, token) =>
        {
            var path = new StringBuilder("collections");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<Collection>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);

    public async Task<Collection?> GetCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"collections/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<Collection>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Collection?> CreateCollectionAsync(CreateCollectionRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("collections", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<Collection>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Collection?> UpdateCollectionAsync(string id, UpdateCollectionRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"collections/{Uri.EscapeDataString(id)}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<Collection>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"collections/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Gets full objects from one collection relationship.</summary>
    public Task<PagedResponse<SearchResult>?> GetCollectionObjectsAsync(
        string collectionId,
        string relationship,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(collectionId, nameof(collectionId));
        ValidateId(relationship, nameof(relationship));
        var path = $"collections/{Uri.EscapeDataString(collectionId)}/{Uri.EscapeDataString(relationship)}";
        return GetPagedAsync<SearchResult>(
            (nextCursor, token) => GetPageAsync<SearchResult>(path, limit, nextCursor, token),
            cursor,
            fetchAll,
            cancellationToken);
    }

    /// <summary>Gets descriptors from one collection relationship.</summary>
    public Task<PagedResponse<Relationship>?> GetCollectionRelationshipDescriptorsAsync(
        string collectionId,
        string relationship,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(collectionId, nameof(collectionId));
        ValidateId(relationship, nameof(relationship));
        var path = $"collections/{Uri.EscapeDataString(collectionId)}/relationships/{Uri.EscapeDataString(relationship)}";
        return GetPagedAsync<Relationship>(
            (nextCursor, token) => GetPageAsync<Relationship>(path, limit, nextCursor, token),
            cursor,
            fetchAll,
            cancellationToken);
    }

    /// <summary>Adds descriptors to one collection relationship.</summary>
    public Task AddCollectionItemsAsync(
        string collectionId,
        string relationship,
        RelationshipDescriptorsRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateId(collectionId, nameof(collectionId));
        ValidateId(relationship, nameof(relationship));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        request.Validate();
        return SendJsonAsync(
            HttpMethod.Post,
            $"collections/{Uri.EscapeDataString(collectionId)}/{Uri.EscapeDataString(relationship)}",
            request,
            cancellationToken);
    }

    /// <summary>Deletes descriptors from one collection relationship.</summary>
    public Task DeleteCollectionItemsAsync(
        string collectionId,
        string relationship,
        RelationshipDescriptorsRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateId(collectionId, nameof(collectionId));
        ValidateId(relationship, nameof(relationship));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        request.Validate();
        return SendJsonAsync(
            HttpMethod.Delete,
            $"collections/{Uri.EscapeDataString(collectionId)}/{Uri.EscapeDataString(relationship)}",
            request,
            cancellationToken);
    }

}
