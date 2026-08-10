using System;
using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Provides one authenticated VirusTotal client for a cmdlet invocation.</summary>
public abstract class VirusTotalCmdlet : AsyncPSCmdlet
{
    private IVirusTotalClient? _ownedClient;

    /// <summary>VirusTotal API key used when <see cref="Client"/> is not supplied.</summary>
    [Parameter]
    public string? ApiKey { get; set; }

    /// <summary>Existing client to reuse. The cmdlet never disposes caller-owned clients.</summary>
    [Parameter]
    public IVirusTotalClient? Client { get; set; }

    /// <summary>The validated client for the current invocation.</summary>
    protected IVirusTotalClient ActiveClient => Client ?? _ownedClient
        ?? throw new InvalidOperationException("The VirusTotal client has not been initialized.");

    /// <inheritdoc/>
    protected override Task BeginProcessingAsync()
    {
        var hasApiKey = !string.IsNullOrWhiteSpace(ApiKey);
        if (hasApiKey == (Client is not null))
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Specify exactly one of ApiKey or Client."),
                "VirusTotalAuthenticationRequired",
                ErrorCategory.AuthenticationError,
                null));
        }

        if (Client is null)
        {
            _ownedClient = VirusTotalClient.Create(ApiKey!);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task EndProcessingAsync()
    {
        _ownedClient?.Dispose();
        _ownedClient = null;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        _ownedClient?.Dispose();
        _ownedClient = null;
        base.Dispose();
    }
}
