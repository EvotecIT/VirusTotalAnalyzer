using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Comment
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public CommentData Data { get; set; } = new();
}

public sealed class CommentData
{
    public CommentAttributes Attributes { get; set; } = new();
}

public sealed class CommentAttributes
{
    public DateTimeOffset Date { get; set; }

    public string Text { get; set; } = string.Empty;
}

public sealed class CommentsResponse
{
    public List<Comment> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class CommentResponse
{
    public Comment Data { get; set; } = new();
}

public sealed class CreateCommentRequest
{
    public CreateCommentData Data { get; set; } = new();
}

public sealed class CreateCommentData
{
    public string Type { get; set; } = "comment";

    public CreateCommentAttributes Attributes { get; set; } = new();
}

public sealed class CreateCommentAttributes
{
    public string Text { get; set; } = string.Empty;
}