using System.Runtime.Serialization;

namespace VirusTotalAnalyzer;

/// <summary>
/// Represents resource types supported by the VirusTotal v3 API.
/// </summary>
public enum ResourceType
{
    /// <summary>An unrecognized or missing API resource type.</summary>
    Unknown = 0,

    [EnumMember(Value = "file")]
    File = 1,

    [EnumMember(Value = "url")]
    Url = 2,

    [EnumMember(Value = "ip_address")]
    IpAddress = 3,

    [EnumMember(Value = "domain")]
    Domain = 4,

    [EnumMember(Value = "analysis")]
    Analysis = 5,

    [EnumMember(Value = "private_analysis")]
    PrivateAnalysis = 6,

    [EnumMember(Value = "comment")]
    Comment = 7,

    [EnumMember(Value = "vote")]
    Vote = 8,

    [EnumMember(Value = "relationship")]
    Relationship = 9,

    [EnumMember(Value = "graph")]
    Graph = 10,

    [EnumMember(Value = "ssl_cert")]
    SslCertificate = 11,

    [EnumMember(Value = "user")]
    User = 12,

    [EnumMember(Value = "group")]
    Group = 13,

    [EnumMember(Value = "collection")]
    Collection = 14,

    [EnumMember(Value = "zip_file")]
    ZipFile = 15,

    [EnumMember(Value = "livehunt_notification")]
    LivehuntNotification = 16,

    [EnumMember(Value = "retrohunt_job")]
    RetrohuntJob = 17,

    [EnumMember(Value = "intelligence_hunting_ruleset")]
    IntelligenceHuntingRuleset = 19,

    [EnumMember(Value = "file_behaviour")]
    FileBehaviour = 20,

    [EnumMember(Value = "whois")]
    Whois = 21
}
