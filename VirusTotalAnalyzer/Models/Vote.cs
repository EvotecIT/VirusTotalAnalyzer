using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Vote
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public VoteData Data { get; set; } = new();
}

public sealed class VoteData
{
    public VoteAttributes Attributes { get; set; } = new();
}

public sealed class VoteAttributes
{
    public DateTimeOffset Date { get; set; }

    public VoteVerdict Verdict { get; set; }
}

public sealed class VotesResponse
{
    public List<Vote> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class VoteResponse
{
    public Vote Data { get; set; } = new();
}

public sealed class CreateVoteRequest
{
    public CreateVoteData Data { get; set; } = new();
}

public sealed class CreateVoteData
{
    public string Type { get; set; } = "vote";

    public CreateVoteAttributes Attributes { get; set; } = new();
}

public sealed class CreateVoteAttributes
{
    public VoteVerdict Verdict { get; set; }
}