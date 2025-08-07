using System;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

/// <summary>
/// Builds a <see cref="CreateCommentRequest"/> using a fluent API.
/// </summary>
public sealed class CommentRequestBuilder
{
    private readonly CreateCommentRequest _request = new();

    /// <summary>
    /// Sets the comment text.
    /// </summary>
    public CommentRequestBuilder WithText(string text)
    {
        _request.Data.Attributes.Text = text ?? throw new ArgumentNullException(nameof(text));
        return this;
    }

    /// <summary>
    /// Builds the request.
    /// </summary>
    public CreateCommentRequest Build() => _request;
}

