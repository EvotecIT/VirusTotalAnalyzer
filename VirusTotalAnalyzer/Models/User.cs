using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents a VirusTotal user object.</summary>
public sealed class User
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public UserAttributes Attributes { get; set; } = new();
}

/// <summary>Contains the documented, non-secret attributes of a VirusTotal user.</summary>
public sealed class UserAttributes
{
    /// <summary>Gets or sets the user's first name when visible to the caller.</summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>Gets or sets the user's last name when visible to the caller.</summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>Gets or sets the user's public profile phrase.</summary>
    public string ProfilePhrase { get; set; } = string.Empty;

    /// <summary>Gets or sets the user's community reputation.</summary>
    public int? Reputation { get; set; }

    /// <summary>Gets or sets the account status.</summary>
    public string Status { get; set; } = string.Empty;

    /// <summary>Gets or sets the last login timestamp when visible to the caller.</summary>
    public DateTimeOffset? LastLogin { get; set; }

    /// <summary>Gets or sets the account creation timestamp.</summary>
    public DateTimeOffset? UserSince { get; set; }

    /// <summary>Gets or sets whether two-factor authentication is enabled when visible to the caller.</summary>
    [JsonPropertyName("has_2fa")]
    public bool? Has2Fa { get; set; }

    /// <summary>Gets or sets the privileges visible to the caller, keyed by privilege name.</summary>
    public Dictionary<string, UserPrivilege> Privileges { get; set; } = new();

    /// <summary>Gets or sets the quotas visible to the caller, keyed by quota name.</summary>
    public Dictionary<string, UserQuota> Quotas { get; set; } = new();
}

/// <summary>Describes one user privilege.</summary>
public sealed class UserPrivilege
{
    /// <summary>Gets or sets whether the privilege is granted.</summary>
    public bool Granted { get; set; }

    /// <summary>Gets or sets when the privilege expires.</summary>
    public DateTimeOffset? ExpirationDate { get; set; }

    /// <summary>Gets or sets the group from which the privilege is inherited.</summary>
    public string? InheritedFrom { get; set; }

    /// <summary>Gets or sets the quota group through which the privilege is inherited.</summary>
    public string? InheritedVia { get; set; }
}

/// <summary>Describes consumption of one user quota.</summary>
public sealed class UserQuota
{
    /// <summary>Gets or sets the maximum allowed value.</summary>
    public long Allowed { get; set; }

    /// <summary>Gets or sets the consumed value.</summary>
    public long Used { get; set; }
}
