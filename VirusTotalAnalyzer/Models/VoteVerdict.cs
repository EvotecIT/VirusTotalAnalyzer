using System.Runtime.Serialization;

namespace VirusTotalAnalyzer.Models;

public enum VoteVerdict
{
    [EnumMember(Value = "harmless")]
    Harmless,
    [EnumMember(Value = "malicious")]
    Malicious
}
