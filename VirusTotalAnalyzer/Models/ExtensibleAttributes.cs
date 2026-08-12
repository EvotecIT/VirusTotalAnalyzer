using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

/// <summary>
/// Base class for VirusTotal attribute objects that preserves fields introduced by the service
/// before the library has added strongly typed properties for them.
/// </summary>
public abstract class ExtensibleAttributes
{
    /// <summary>Gets or sets attributes that are not represented by a strongly typed property.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> AdditionalProperties { get; set; } = new();
}
