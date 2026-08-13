using System;
using System.Globalization;

namespace VirusTotalAnalyzer;

/// <summary>Options supported by VirusTotal Private Scanning file uploads.</summary>
public sealed class PrivateFileUploadOptions
{
    public bool? DisableSandbox { get; set; }

    public bool? EnableInternet { get; set; }

    public bool? InterceptTls { get; set; }

    public string? CommandLine { get; set; }

    public string? Password { get; set; }

    public int? RetentionPeriodDays { get; set; }

    public string? StorageRegion { get; set; }

    public string? InteractionSandbox { get; set; }

    public int? InteractionTimeoutSeconds { get; set; }

    public string? Locale { get; set; }

    internal void Validate()
    {
        if (RetentionPeriodDays is < 1 or > 28)
        {
            throw new ArgumentOutOfRangeException(nameof(RetentionPeriodDays), "Retention must be between 1 and 28 days.");
        }
        if (InteractionTimeoutSeconds is < 60 or > 1800)
        {
            throw new ArgumentOutOfRangeException(nameof(InteractionTimeoutSeconds), "Interaction timeout must be between 60 and 1800 seconds.");
        }
        if (StorageRegion is not null &&
            !string.Equals(StorageRegion, "US", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(StorageRegion, "EU", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Storage region must be US or EU.", nameof(StorageRegion));
        }
    }

    internal void AddFormFields(MultipartFormDataBuilder builder)
    {
        if (DisableSandbox.HasValue) builder.WithFormField("disable_sandbox", ToBoolean(DisableSandbox.Value));
        if (EnableInternet.HasValue) builder.WithFormField("enable_internet", ToBoolean(EnableInternet.Value));
        if (InterceptTls.HasValue) builder.WithFormField("intercept_tls", ToBoolean(InterceptTls.Value));
        if (!string.IsNullOrEmpty(CommandLine)) builder.WithFormField("command_line", CommandLine!);
        if (!string.IsNullOrEmpty(Password)) builder.WithFormField("password", Password!);
        if (RetentionPeriodDays.HasValue) builder.WithFormField("retention_period_days", RetentionPeriodDays.Value.ToString(CultureInfo.InvariantCulture));
        if (!string.IsNullOrEmpty(StorageRegion)) builder.WithFormField("storage_region", StorageRegion!.ToUpperInvariant());
        if (!string.IsNullOrEmpty(InteractionSandbox)) builder.WithFormField("interaction_sandbox", InteractionSandbox!);
        if (InteractionTimeoutSeconds.HasValue) builder.WithFormField("interaction_timeout", InteractionTimeoutSeconds.Value.ToString(CultureInfo.InvariantCulture));
        if (!string.IsNullOrEmpty(Locale)) builder.WithFormField("locale", Locale!);
    }

    private static string ToBoolean(bool value) => value ? "true" : "false";
}
