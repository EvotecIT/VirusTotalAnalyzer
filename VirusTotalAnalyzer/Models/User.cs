using System.Runtime.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class User
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public UserData Data { get; set; } = new();
}

public sealed class UserData
{
    public UserAttributes Attributes { get; set; } = new();
}

public sealed class UserAttributes
{
    public string Username { get; set; } = string.Empty;

    public UserRole Role { get; set; }
}

public enum UserRole
{
    [EnumMember(Value = "user")]
    User,

    [EnumMember(Value = "admin")]
    Admin
}