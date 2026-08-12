using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class PeInfoAttributes
{
    public string? Imphash { get; set; }

    public string? MachineType { get; set; }

    public List<PeSection> Sections { get; set; } = new();
}

public sealed class PeSection
{
    public string? Name { get; set; }
}
