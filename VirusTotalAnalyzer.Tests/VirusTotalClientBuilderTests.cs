using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class VirusTotalClientBuilderTests
{
    [Fact]
    public async Task CreateCommentAsync_WithRequest_PostsComment()
    {
        var json = @"{""data"":{""id"":""c1"",""type"":""comment"",""data"":{""attributes"":{""date"":1,""text"":""hello""}}}}";
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var request = new CommentRequestBuilder()
            .WithText("hello")
            .Build();
        var comment = await client.CreateCommentAsync(ResourceType.File, "abc", request);

        Assert.NotNull(comment);
        Assert.Single(handler.Requests);
        Assert.Equal("/api/v3/files/abc/comments", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hello\"", handler.Contents[0]);
    }

    [Fact]
    public async Task CreateVoteAsync_WithRequest_PostsVerdict()
    {
        var json = @"{""data"":{""id"":""v1"",""type"":""vote"",""data"":{""attributes"":{""date"":1,""verdict"":""malicious""}}}}";
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var request = new VoteRequestBuilder()
            .WithVerdict(VoteVerdict.Malicious)
            .Build();
        var vote = await client.CreateVoteAsync(ResourceType.File, "abc", request);

        Assert.NotNull(vote);
        Assert.Single(handler.Requests);
        Assert.Equal("/api/v3/files/abc/votes", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Contents[0]);
}

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly System.Collections.Generic.Queue<HttpResponseMessage> _responses;
        public System.Collections.Generic.List<HttpRequestMessage> Requests { get; } = new();
        public System.Collections.Generic.List<string?> Contents { get; } = new();

        public RecordingHandler(params HttpResponseMessage[] responses)
            => _responses = new System.Collections.Generic.Queue<HttpResponseMessage>(responses);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (request.Content != null)
            {
#if NETFRAMEWORK
                var text = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
                var text = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
#endif
                Contents.Add(text);
            }
            else
            {
                Contents.Add(null);
            }
            return _responses.Dequeue();
        }
    }
}

