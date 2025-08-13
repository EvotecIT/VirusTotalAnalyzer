using System;
using System.Management.Automation;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

[Cmdlet(VerbsCommon.Get, "VtYaraRuleset")]
[OutputType(typeof(YaraRuleset))]
public sealed class GetVtYaraRulesetCommand : PSCmdlet
{
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    [Parameter(Position = 0)]
    public string? Id { get; set; }

    [Parameter]
    public int? Limit { get; set; }

    [Parameter]
    public string? Cursor { get; set; }

    protected override void ProcessRecord()
    {
        using var client = VirusTotalClient.Create(ApiKey);
        if (string.IsNullOrEmpty(Id))
        {
            var page = client.ListYaraRulesetsAsync(Limit, Cursor, fetchAll: false).GetAwaiter().GetResult();
            if (page != null)
            {
                WriteObject(page.Data, true);
                if (!string.IsNullOrEmpty(page.NextCursor))
                {
                    WriteVerbose($"Next cursor: {page.NextCursor}");
                }
            }
        }
        else
        {
            var ruleset = client.GetYaraRulesetAsync(Id).GetAwaiter().GetResult();
            if (ruleset != null)
            {
                WriteObject(ruleset);
            }
        }
    }
}

