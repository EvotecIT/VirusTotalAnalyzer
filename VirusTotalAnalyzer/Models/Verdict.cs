using System.Runtime.Serialization;

namespace VirusTotalAnalyzer.Models;

public enum Verdict
{
    [EnumMember(Value = "harmless")] Harmless,
    [EnumMember(Value = "undetected")] Undetected,
    [EnumMember(Value = "suspicious")] Suspicious,
    [EnumMember(Value = "malicious")] Malicious,
    [EnumMember(Value = "timeout")] Timeout,
    [EnumMember(Value = "failure")] Failure,
    [EnumMember(Value = "type-unsupported")] TypeUnsupported
}
