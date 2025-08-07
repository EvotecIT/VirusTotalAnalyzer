using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

/// <summary>
/// Builds a <see cref="CreateVoteRequest"/> using a fluent API.
/// </summary>
public sealed class VoteRequestBuilder
{
    private readonly CreateVoteRequest _request = new();

    /// <summary>
    /// Sets the vote verdict.
    /// </summary>
    public VoteRequestBuilder WithVerdict(VoteVerdict verdict)
    {
        _request.Data.Attributes.Verdict = verdict;
        return this;
    }

    /// <summary>
    /// Builds the request.
    /// </summary>
    public CreateVoteRequest Build() => _request;
}

