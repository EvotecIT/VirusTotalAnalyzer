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
    public async Task<Comment?> GetCommentAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"{GetPath(ResourceType.Comment)}/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<CommentResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<CommentsResponse?> GetCommentsAsync(ResourceType resourceType, string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new StringBuilder($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/comments");
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
        return await JsonSerializer.DeserializeAsync<CommentsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Vote?> GetVoteAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"{GetPath(ResourceType.Vote)}/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<VoteResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<VotesResponse?> GetVotesAsync(ResourceType resourceType, string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new StringBuilder($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/votes");
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
        return await JsonSerializer.DeserializeAsync<VotesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public Task<Comment?> CreateCommentAsync(ResourceType resourceType, string id, string text, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var request = new CommentRequestBuilder()
            .WithText(text)
            .Build();
        return CreateCommentAsync(resourceType, id, request, cancellationToken);
    }

    public async Task<Comment?> CreateCommentAsync(ResourceType resourceType, string id, CreateCommentRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        ArgumentNullException.ThrowIfNull(request);
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/comments", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<CommentResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public Task<Vote?> CreateVoteAsync(ResourceType resourceType, string id, VoteVerdict verdict, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var request = new VoteRequestBuilder()
            .WithVerdict(verdict)
            .Build();
        return CreateVoteAsync(resourceType, id, request, cancellationToken);
    }

    public async Task<Vote?> CreateVoteAsync(ResourceType resourceType, string id, CreateVoteRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        ArgumentNullException.ThrowIfNull(request);
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/votes", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<VoteResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task DeleteItemAsync(ResourceType resourceType, string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<User?> GetUserAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"users/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<User>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<UserPrivileges?> GetUserPrivilegesAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"users/{Uri.EscapeDataString(id)}/privileges", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<UserPrivileges>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<UserQuota?> GetUserQuotaAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"users/{Uri.EscapeDataString(id)}/quotas", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<UserQuota>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }
}
