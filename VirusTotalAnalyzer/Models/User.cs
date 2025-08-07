using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class User
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public UserData Data { get; set; } = new();
}

public sealed class UserData
{
    public UserAttributes Attributes { get; set; } = new();
}

public sealed class UserAttributes
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("role")]
    public UserRole Role { get; set; }
}

public enum UserRole
{
    [EnumMember(Value = "user")]
    User,

    [EnumMember(Value = "admin")]
    Admin
}
