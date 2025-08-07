using System.Runtime.Serialization;

namespace VirusTotalAnalyzer;

public enum VoteValue
{
    [EnumMember(Value = "harmless")] Harmless,
    [EnumMember(Value = "malicious")] Malicious,
    [EnumMember(Value = "suspicious")] Suspicious,
    [EnumMember(Value = "undetected")] Undetected
}
