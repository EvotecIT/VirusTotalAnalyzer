using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public sealed class VirusTotalV3ContractTests
{
    [Fact]
    public async Task FileReport_PreservesUnmodeledAttributes_AndDeserializesNestedFileMetadata()
    {
        const string json = "{\"data\":{\"id\":\"hash\",\"type\":\"file\",\"attributes\":{" +
            "\"md5\":\"abc\",\"pe_info\":{\"imphash\":\"imp\",\"sections\":[{\"name\":\".text\"}]} ," +
            "\"popular_threat_classification\":{\"suggested_threat_label\":\"eicar\",\"popular_threat_category\":[{\"count\":2,\"value\":\"virus\"}]}," +
            "\"crowdsourced_yara_results\":[{\"rule_name\":\"EICAR\",\"match_in_subfile\":true}]," +
            "\"crowdsourced_ids_results\":[{\"rule_id\":\"1\",\"alert_severity\":\"low\",\"rule_category\":\"test\",\"rule_msg\":\"message\",\"rule_source\":\"community\",\"alert_context\":[{\"src_ip\":\"1.1.1.1\",\"dest_port\":443}]}]," +
            "\"trid\":[{\"file_type\":\"EICAR antivirus test file\",\"probability\":100.0}]," +
            "\"future_attribute\":{\"enabled\":true}}}}";
        var handler = JsonHandler(json);
        using var client = CreateClient(handler);

        var report = await client.GetFileReportAsync("hash");

        Assert.NotNull(report);
        Assert.Null(report!.Attributes.CreationDate);
        Assert.Equal("imp", report.Attributes.PeInfo!.Imphash);
        Assert.Equal(".text", Assert.Single(report.Attributes.PeInfo.Sections).Name);
        Assert.Equal("eicar", report.Attributes.PopularThreatClassification!.SuggestedThreatLabel);
        Assert.Equal("virus", Assert.Single(report.Attributes.PopularThreatClassification.PopularThreatCategory).Value);
        Assert.Equal("EICAR", Assert.Single(report.Attributes.CrowdsourcedYaraResults).RuleName);
        Assert.True(Assert.Single(report.Attributes.CrowdsourcedYaraResults).MatchInSubfile is true);
        var idsResult = Assert.Single(report.Attributes.CrowdsourcedIdsResults);
        Assert.Equal("low", idsResult.AlertSeverity);
        Assert.Equal("message", idsResult.RuleMsg);
        Assert.Equal("1.1.1.1", Assert.Single(idsResult.AlertContext).SrcIp);
        Assert.Equal("EICAR antivirus test file", Assert.Single(report.Attributes.Trid).FileType);
        Assert.True(report.Attributes.AdditionalProperties.ContainsKey("future_attribute"));
    }

    [Fact]
    public async Task Search_SeparatesPublicAndIntelligenceEndpoints()
    {
        var handler = new QueueHandler(JsonResponse("{\"data\":[]}"), JsonResponse("{\"data\":[]}"));
        using var client = CreateClient(handler);

        await client.SearchAsync("example.com", limit: 5, cursor: "public cursor");
        await client.SearchIntelligenceAsync("type:file", limit: 25, cursor: "intel cursor", order: "last_submission_date-", descriptor: "file");

        Assert.Equal("/api/v3/search", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("?query=example.com&limit=5&cursor=public%20cursor", handler.Requests[0].RequestUri!.Query);
        Assert.Equal("/api/v3/intelligence/search", handler.Requests[1].RequestUri!.AbsolutePath);
        Assert.Equal("?query=type%3Afile&limit=25&cursor=intel%20cursor&order=last_submission_date-&descriptor=file", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task GraphPermissions_UseRelationshipRoutesAndCompactDescriptors()
    {
        var handler = new QueueHandler(
            JsonResponse("{\"data\":[]}"),
            JsonResponse("{\"data\":[]}"),
            new HttpResponseMessage(HttpStatusCode.NoContent));
        using var client = CreateClient(handler);
        var request = new GraphPermissionRequest
        {
            Data = { new RelationshipDescriptor { Id = "alice", Type = ResourceType.User } }
        };

        await client.GetGraphPermissionsAsync("graph", GraphPermission.Viewer, limit: 10, cursor: "next");
        await client.GrantGraphPermissionAsync("graph", GraphPermission.Editor, request);
        await client.RevokeGraphPermissionAsync("graph", GraphPermission.Editor, "alice");

        Assert.Equal("/api/v3/graphs/graph/relationships/viewers", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("?limit=10&cursor=next", handler.Requests[0].RequestUri!.Query);
        Assert.Equal("/api/v3/graphs/graph/relationships/editors", handler.Requests[1].RequestUri!.AbsolutePath);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Contains("\"id\":\"alice\"", handler.Contents[1]);
        Assert.DoesNotContain("links", handler.Contents[1]);
        Assert.Equal("/api/v3/graphs/graph/relationships/editors/alice", handler.Requests[2].RequestUri!.AbsolutePath);
        Assert.Equal(HttpMethod.Delete, handler.Requests[2].Method);
    }

    [Fact]
    public async Task CreateGraph_SerializesCurrentGraphDataNodesAndLinksSchema()
    {
        var handler = new SingleResponseHandler(JsonResponse("{\"data\":{\"id\":\"g1\",\"type\":\"graph\"}}"));
        using var client = CreateClient(handler);
        var request = new CreateGraphRequest
        {
            Data =
            {
                Attributes =
                {
                    GraphData = new GraphData { Description = "Investigation", Version = "5.0.0" },
                    Private = true,
                    Position = new GraphPosition { X = 10, Y = 20, Scale = 1.5 },
                    Nodes = new() { new GraphNode { EntityId = "abc", Type = "file", Index = 0 } },
                    Links = new() { new GraphConnection { ConnectionType = "contacted_ips", Source = "abc", Target = "1.1.1.1" } }
                }
            }
        };

        var graph = await client.CreateGraphAsync(request);

        Assert.Equal("g1", graph!.Id);
        Assert.Equal("/api/v3/graphs", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"graph_data\":{\"description\":\"Investigation\",\"version\":\"5.0.0\"}", handler.Content);
        Assert.Contains("\"nodes\":[{", handler.Content);
        Assert.Contains("\"links\":[{", handler.Content);
        Assert.Contains("\"position\":{\"scale\":1.5,\"x\":10,\"y\":20}", handler.Content);
        Assert.Contains("\"private\":true", handler.Content);
        Assert.DoesNotContain("\"name\"", handler.Content);
    }

    [Fact]
    public async Task CollectionMutations_SendDescriptorsToTheRelationshipEndpoint()
    {
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.NoContent),
            new HttpResponseMessage(HttpStatusCode.NoContent));
        using var client = CreateClient(handler);
        var request = new RelationshipDescriptorsRequest
        {
            Data = { new RelationshipDescriptor { Url = "https://example.com/a", Type = ResourceType.Url } }
        };

        await client.AddCollectionItemsAsync("collection", "urls", request);
        await client.DeleteCollectionItemsAsync("collection", "urls", request);

        Assert.All(handler.Requests, item => Assert.Equal("/api/v3/collections/collection/urls", item.RequestUri!.AbsolutePath));
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal(HttpMethod.Delete, handler.Requests[1].Method);
        Assert.All(handler.Contents, content => Assert.Contains("\"url\":\"https://example.com/a\"", content));
        Assert.All(handler.Contents, content => Assert.DoesNotContain("links", content));
    }

    [Fact]
    public async Task ZipFiles_UseIntelligenceJobEndpoints()
    {
        const string zip = "{\"data\":{\"id\":\"zip-1\",\"type\":\"zip_file\",\"attributes\":{\"status\":\"starting\"}}}";
        var handler = new QueueHandler(JsonResponse(zip), JsonResponse(zip), JsonResponse("{\"data\":\"https://storage.example/zip-1\"}"));
        using var client = CreateClient(handler);
        var request = new CreateZipFileRequest { Data = { Password = "infected", Hashes = { "abc" } } };

        var created = await client.CreateZipFileAsync(request);
        var fetched = await client.GetZipFileAsync("zip-1");
        var downloadUrl = await client.GetZipFileDownloadUrlAsync("zip-1");

        Assert.Equal(ResourceType.ZipFile, created!.Type);
        Assert.Equal("zip-1", fetched!.Id);
        Assert.Equal("https://storage.example/zip-1", downloadUrl!.ToString());
        Assert.Equal("/api/v3/intelligence/zip_files", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Contains("\"password\":\"infected\"", handler.Contents[0]);
        Assert.Contains("\"hashes\":[\"abc\"]", handler.Contents[0]);
        Assert.Equal("/api/v3/intelligence/zip_files/zip-1", handler.Requests[1].RequestUri!.AbsolutePath);
        Assert.Equal("/api/v3/intelligence/zip_files/zip-1/download_url", handler.Requests[2].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task NetworkObjectReanalysis_UsesDocumentedAnalyseRoutes()
    {
        const string analysis = "{\"data\":{\"id\":\"a1\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new QueueHandler(JsonResponse(analysis), JsonResponse(analysis));
        using var client = CreateClient(handler);

        await client.ReanalyzeIpAddressAsync("1.1.1.1");
        await client.ReanalyzeDomainAsync("example.com");

        Assert.Equal("/api/v3/ip_addresses/1.1.1.1/analyse", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("/api/v3/domains/example.com/analyse", handler.Requests[1].RequestUri!.AbsolutePath);
        Assert.All(handler.Requests, request => Assert.Equal(HttpMethod.Post, request.Method));
    }

    [Fact]
    public async Task FeedDownloads_UseMinuteAndHourlyPaths_WithoutForwardingAuthentication()
    {
        var firstRedirect = new HttpResponseMessage(HttpStatusCode.Redirect);
        firstRedirect.Headers.Location = new Uri("https://storage.example/minute");
        var secondRedirect = new HttpResponseMessage(HttpStatusCode.Redirect);
        secondRedirect.Headers.Location = new Uri("https://storage.example/hour");
        var apiHandler = new QueueHandler(firstRedirect, secondRedirect);
        var downloadHandler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1 }) },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 2 }) });
        using var apiClient = new HttpClient(apiHandler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") };
        apiClient.DefaultRequestHeaders.Add("x-apikey", "secret");
        using var downloadClient = new HttpClient(downloadHandler);
        using var client = new VirusTotalClient(apiClient, downloadClient);
        var time = new DateTimeOffset(2026, 8, 12, 10, 34, 0, TimeSpan.Zero);

        using (await client.DownloadFeedBatchAsync(FeedType.Files, time, FeedGranularity.Minute)) { }
        using (await client.DownloadFeedBatchAsync(FeedType.FileBehaviors, time, FeedGranularity.Hour)) { }

        Assert.Equal("/api/v3/feeds/files/202608121034", apiHandler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("/api/v3/feeds/file_behaviours/hourly/2026081210", apiHandler.Requests[1].RequestUri!.AbsolutePath);
        Assert.All(downloadHandler.Requests, request => Assert.False(request.Headers.Contains("x-apikey")));
    }

    [Fact]
    public async Task FetchAll_RejectsRepeatedPaginationCursor()
    {
        const string page = "{\"data\":[{\"id\":\"b1\",\"type\":\"file_behaviour\",\"attributes\":{}}],\"meta\":{\"cursor\":\"same\"}}";
        var handler = new QueueHandler(JsonResponse(page), JsonResponse(page));
        using var client = CreateClient(handler);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetFileBehaviorsAsync("hash", fetchAll: true));

        Assert.Contains("repeated pagination cursor", exception.Message);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task RelationshipMutations_RejectInvalidDescriptorsBeforeSending()
    {
        var handler = new QueueHandler();
        using var client = CreateClient(handler);
        var emptyCollectionRequest = new RelationshipDescriptorsRequest();
        var invalidGraphRequest = new GraphPermissionRequest
        {
            Data = { new RelationshipDescriptor { Url = "https://example.com", Type = ResourceType.Url } }
        };

        await Assert.ThrowsAsync<ArgumentException>(
            () => client.AddCollectionItemsAsync("collection", "files", emptyCollectionRequest));
        await Assert.ThrowsAsync<ArgumentException>(
            () => client.GrantGraphPermissionAsync("graph", GraphPermission.Viewer, invalidGraphRequest));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task CreateZipFile_RejectsEmptyHashListBeforeSending()
    {
        var handler = new QueueHandler();
        using var client = CreateClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateZipFileAsync(new CreateZipFileRequest()));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task IocStream_RejectsInvalidLimitBeforeSending()
    {
        var handler = new QueueHandler();
        using var client = CreateClient(handler);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => client.GetIocStreamAsync("entity_type:file", limit: 41));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task PreparedUpload_DoesNotPreReadSeekableStreamsWhenHashIsNotRequested()
    {
        using var source = new CountingSeekableStream(new byte[] { 1, 2, 3, 4 });

        using var prepared = await PreparedUpload.CreateAsync(source, CancellationToken.None);

        Assert.Equal(0, source.BytesRead);
        Assert.Equal(4, prepared.Length);
        Assert.Null(prepared.Sha256);
        Assert.Same(source, prepared.Stream);
    }

    [Fact]
    public async Task PreparedUpload_HashesSeekableStreamsForMonitorVerification()
    {
        using var source = new CountingSeekableStream(Encoding.UTF8.GetBytes("abc"));

        using var prepared = await PreparedUpload.CreateAndHashAsync(source, CancellationToken.None);

        Assert.Equal(3, source.BytesRead);
        Assert.Equal(0, source.Position);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", prepared.Sha256);
    }

    private static VirusTotalClient CreateClient(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        return new VirusTotalClient(httpClient, disposeClient: true);
    }

    private static SingleResponseHandler JsonHandler(string json) => new(JsonResponse(json));

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    private sealed class CountingSeekableStream : Stream
    {
        private readonly MemoryStream _inner;

        public CountingSeekableStream(byte[] data) => _inner = new MemoryStream(data);

        public long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
