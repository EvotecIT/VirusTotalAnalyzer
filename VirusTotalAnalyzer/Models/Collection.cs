

namespace VirusTotalAnalyzer.Models;

public sealed class Collection
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public CollectionData Data { get; set; } = new();
}

public sealed class CollectionData
{
    public CollectionAttributes Attributes { get; set; } = new();
}

public sealed class CollectionAttributes
{
    public string Name { get; set; } = string.Empty;
}

public sealed class CreateCollectionRequest
{
    public CreateCollectionData Data { get; set; } = new();
}

public sealed class CreateCollectionData
{
    public string Type { get; set; } = "collection";

    public CreateCollectionAttributes Attributes { get; set; } = new();
}

public sealed class CreateCollectionAttributes
{
    public string Name { get; set; } = string.Empty;
}

public sealed class UpdateCollectionRequest
{
    public UpdateCollectionData Data { get; set; } = new();
}

public sealed class UpdateCollectionData
{
    public string Type { get; set; } = "collection";

    public UpdateCollectionAttributes Attributes { get; set; } = new();
}

public sealed class UpdateCollectionAttributes
{
    public string? Name { get; set; }
}