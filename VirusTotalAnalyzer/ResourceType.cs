namespace VirusTotalAnalyzer;

/// <summary>
/// Represents resource types supported by the VirusTotal v3 API.
/// </summary>
using System.Runtime.Serialization;

public enum ResourceType
{
    [EnumMember(Value = "file")]
    File,

    [EnumMember(Value = "url")]
    Url,

    [EnumMember(Value = "ip_address")]
    IpAddress,

    [EnumMember(Value = "domain")]
    Domain,

    [EnumMember(Value = "analysis")]
    Analysis,

    [EnumMember(Value = "private_analysis")]
    PrivateAnalysis,

    [EnumMember(Value = "comment")]
    Comment,

    [EnumMember(Value = "vote")]
    Vote,

    [EnumMember(Value = "relationship")]
    Relationship,

    [EnumMember(Value = "search")]
    Search,

    [EnumMember(Value = "feed")]
    Feed,

    [EnumMember(Value = "graph")]
    Graph,

    [EnumMember(Value = "user")]
    User,

    [EnumMember(Value = "collection")]
    Collection,

    [EnumMember(Value = "bundle")]
    Bundle
}
