using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Vote
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public VoteData Data { get; set; } = new();
}

public sealed class VoteData
{
    public VoteAttributes Attributes { get; set; } = new();
}

public sealed class VoteAttributes
{
    [JsonPropertyName("date")]
    public DateTimeOffset Date { get; set; }

    [JsonPropertyName("verdict")]
    public VoteVerdict Verdict { get; set; }
}

public sealed class VotesResponse
{
    [JsonPropertyName("data")]
    public List<Vote> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

public sealed class VoteResponse
{
    [JsonPropertyName("data")]
    public Vote Data { get; set; } = new();
}

public sealed class CreateVoteRequest
{
    [JsonPropertyName("data")]
    public CreateVoteData Data { get; set; } = new();
}

public sealed class CreateVoteData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "vote";

    [JsonPropertyName("attributes")]
    public CreateVoteAttributes Attributes { get; set; } = new();
}

public sealed class CreateVoteAttributes
{
    [JsonPropertyName("verdict")]
    public VoteVerdict Verdict { get; set; }
}
