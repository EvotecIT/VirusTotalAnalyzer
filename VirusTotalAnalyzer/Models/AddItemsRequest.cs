using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class AddItemsRequest
{
    public List<Relationship> Data { get; set; } = new();
}

