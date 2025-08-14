using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FilePeInfo
{
    public PeInfoData Data { get; set; } = new();
}

public sealed class PeInfoData
{
    public PeInfoAttributes Attributes { get; set; } = new();
}

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