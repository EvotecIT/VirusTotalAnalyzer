using System.Management.Automation;

namespace VirusTotalAnalyzer.PowerShell;

[Cmdlet(VerbsCommon.Remove, "VtYaraRuleset", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
public sealed class RemoveVtYaraRulesetCommand : PSCmdlet
{
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    [Parameter(Mandatory = true, Position = 0)]
    public string Id { get; set; } = string.Empty;

    protected override void ProcessRecord()
    {
        if (ShouldProcess(Id))
        {
            using var client = VirusTotalClient.Create(ApiKey);
            client.DeleteYaraRulesetAsync(Id).GetAwaiter().GetResult();
        }
    }
}

