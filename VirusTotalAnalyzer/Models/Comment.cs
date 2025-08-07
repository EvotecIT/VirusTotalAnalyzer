using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Comment
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public CommentData Data { get; set; } = new();
}

public sealed class CommentData
{
    public CommentAttributes Attributes { get; set; } = new();
}

public sealed class CommentAttributes
{
    [JsonPropertyName("date")]
    public long Date { get; set; }

    [JsonPropertyName("text")]
    public string Text { get; set; } = string.Empty;
}

public sealed class CommentsResponse
{
    [JsonPropertyName("data")]
    public List<Comment> Data { get; set; } = new();
}
