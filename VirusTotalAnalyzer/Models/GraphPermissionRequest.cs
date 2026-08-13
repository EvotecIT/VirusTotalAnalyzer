using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace VirusTotalAnalyzer.Models;

/// <summary>Users or groups to grant access to a VirusTotal Graph.</summary>
public sealed class GraphPermissionRequest
{
    public List<RelationshipDescriptor> Data { get; set; } = new();

    internal void Validate()
    {
        if (Data is null || Data.Count == 0)
        {
            throw new ArgumentException("At least one user or group descriptor is required.", nameof(Data));
        }
        if (Data.Any(item => (item.Type != ResourceType.User && item.Type != ResourceType.Group) ||
                             string.IsNullOrWhiteSpace(item.Id) ||
                             !string.IsNullOrWhiteSpace(item.Url)))
        {
            throw new ArgumentException("Graph permissions accept user or group descriptors with a non-empty id.", nameof(Data));
        }
    }
}

/// <summary>A user or group that can access a VirusTotal Graph.</summary>
public sealed class GraphPrincipal
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public Dictionary<string, JsonElement> Attributes { get; set; } = new();
}
