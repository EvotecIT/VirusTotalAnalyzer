using System.Runtime.Serialization;

namespace VirusTotalAnalyzer;

/// <summary>
/// Represents resource types supported by the VirusTotal v3 API.
/// </summary>
public enum ResourceType
{
    /// <summary>An unrecognized or missing API resource type.</summary>
    Unknown,

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

    [EnumMember(Value = "graph")]
    Graph,

    [EnumMember(Value = "ssl_certificate")]
    SslCertificate,

    [EnumMember(Value = "user")]
    User,

    [EnumMember(Value = "group")]
    Group,

    [EnumMember(Value = "collection")]
    Collection,

    [EnumMember(Value = "zip_file")]
    ZipFile,

    [EnumMember(Value = "livehunt_notification")]
    LivehuntNotification,

    [EnumMember(Value = "retrohunt_job")]
    RetrohuntJob,

    [EnumMember(Value = "retrohunt_notification")]
    RetrohuntNotification,

    [EnumMember(Value = "intelligence_hunting_ruleset")]
    IntelligenceHuntingRuleset,

    [EnumMember(Value = "file_behaviour")]
    FileBehaviour
}
