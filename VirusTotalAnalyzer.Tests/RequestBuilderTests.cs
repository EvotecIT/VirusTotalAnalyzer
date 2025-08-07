using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class RequestBuilderTests
{
    [Fact]
    public void CommentRequestBuilder_SetsText()
    {
        var request = new CommentRequestBuilder()
            .WithText("hello")
            .Build();

        Assert.Equal("hello", request.Data.Attributes.Text);
    }

    [Fact]
    public void VoteRequestBuilder_SetsVerdict()
    {
        var request = new VoteRequestBuilder()
            .WithVerdict(VoteVerdict.Harmless)
            .Build();

        Assert.Equal(VoteVerdict.Harmless, request.Data.Attributes.Verdict);
    }
}

