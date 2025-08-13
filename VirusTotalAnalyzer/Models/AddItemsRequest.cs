using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class AddItemsRequest
{
    [JsonPropertyName("data")]
    public List<Relationship> Data { get; set; } = new();
}

