using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class PathEncodingTests
{
    [Fact]
    public async Task GetUserAsync_EncodesIdInPath()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var id = "user/id?test";
        await client.GetUserAsync(id);

        Assert.NotNull(handler.Request);
        Assert.Equal($"/api/v3/users/{Uri.EscapeDataString(id)}", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateCommentAsync_EncodesIdInPath()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var id = "file/id#1";
        var request = new CommentRequestBuilder().WithText("text").Build();
        await client.CreateCommentAsync(ResourceType.File, id, request);

        Assert.NotNull(handler.Request);
        Assert.Equal($"/api/v3/files/{Uri.EscapeDataString(id)}/comments", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task DeleteGraphCommentAsync_EncodesIdsInPath()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var graphId = "graph/id#1";
        var commentId = "comment/id?2";
        await client.DeleteGraphCommentAsync(graphId, commentId);

        Assert.NotNull(handler.Request);
        Assert.Equal($"/api/v3/graphs/{Uri.EscapeDataString(graphId)}/comments/{Uri.EscapeDataString(commentId)}", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task DeleteGraphCollaboratorAsync_EncodesIdsInPath()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var graphId = "graph/id#1";
        var username = "user/name?2";
        await client.DeleteGraphCollaboratorAsync(graphId, username);

        Assert.NotNull(handler.Request);
        Assert.Equal($"/api/v3/graphs/{Uri.EscapeDataString(graphId)}/collaborators/{Uri.EscapeDataString(username)}", handler.Request!.RequestUri!.AbsolutePath);
    }
}

