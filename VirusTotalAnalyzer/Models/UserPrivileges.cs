using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class UserPrivileges
{
    public Dictionary<string, PrivilegeData> Data { get; set; } = new();
}

public sealed class PrivilegeData
{
    public bool Allowed { get; set; }
}