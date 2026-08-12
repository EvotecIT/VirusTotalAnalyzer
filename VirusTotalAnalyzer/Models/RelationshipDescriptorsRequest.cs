using System;
using System.Collections.Generic;
using System.Linq;

namespace VirusTotalAnalyzer.Models;

/// <summary>Object descriptors used to mutate a VirusTotal relationship.</summary>
public sealed class RelationshipDescriptorsRequest
{
    public List<RelationshipDescriptor> Data { get; set; } = new();

    internal void Validate()
    {
        if (Data is null || Data.Count == 0)
        {
            throw new ArgumentException("At least one relationship descriptor is required.", nameof(Data));
        }
        if (Data.Any(item => item.Type == ResourceType.Unknown ||
                             string.IsNullOrWhiteSpace(item.Id) == string.IsNullOrWhiteSpace(item.Url)))
        {
            throw new ArgumentException("Each descriptor requires a type and exactly one non-empty id or URL.", nameof(Data));
        }
    }
}
