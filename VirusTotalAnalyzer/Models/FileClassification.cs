

namespace VirusTotalAnalyzer.Models;

public sealed class FileClassification
{
    public FileClassificationData Data { get; set; } = new();
}

public sealed class FileClassificationData
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public FileClassificationAttributes Attributes { get; set; } = new();
}

public sealed class FileClassificationAttributes
{
    public string? PopularThreatName { get; set; }

    public string? PopularThreatCategory { get; set; }

    public string? SuggestedThreatLabel { get; set; }
}

