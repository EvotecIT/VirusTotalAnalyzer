using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class AddCollaboratorsRequest
{
    public List<Relationship> Data { get; set; } = new();
}

