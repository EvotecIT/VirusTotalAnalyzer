using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Bundle
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public BundleData Data { get; set; } = new();
}

public sealed class BundleData
{
    public BundleAttributes Attributes { get; set; } = new();
}

public sealed class BundleAttributes
{
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    public List<Relationship> Files { get; set; } = new();
}

public sealed class CreateBundleRequest
{
    public CreateBundleData Data { get; set; } = new();
}

public sealed class CreateBundleData
{
    public string Type { get; set; } = "bundle";

    public CreateBundleAttributes Attributes { get; set; } = new();
}

public sealed class CreateBundleAttributes
{
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    public List<Relationship> Files { get; set; } = new();
}

public sealed class UpdateBundleRequest
{
    public UpdateBundleData Data { get; set; } = new();
}

public sealed class UpdateBundleData
{
    public string Type { get; set; } = "bundle";

    public UpdateBundleAttributes Attributes { get; set; } = new();
}

public sealed class UpdateBundleAttributes
{
    public string? Name { get; set; }

    public string? Description { get; set; }

    public List<Relationship> Files { get; set; } = new();
}