using System.Collections.Generic;
using System.Management.Automation;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

[Cmdlet(VerbsCommon.Set, "VtYaraRuleset")]
[OutputType(typeof(YaraRuleset))]
public sealed class SetVtYaraRulesetCommand : PSCmdlet
{
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    [Parameter(Mandatory = true, Position = 0)]
    public string Id { get; set; } = string.Empty;

    [Parameter]
    public string? Name { get; set; }

    [Parameter]
    public string? Rules { get; set; }

    [Parameter]
    public string[]? WatcherId { get; set; }

    protected override void ProcessRecord()
    {
        var request = new YaraRulesetRequest();
        if (Name != null)
        {
            request.Data.Attributes.Name = Name;
        }
        if (Rules != null)
        {
            request.Data.Attributes.Rules = Rules;
        }
        if (WatcherId != null)
        {
            request.Data.Attributes.Watchers = new List<YaraWatcher>();
            foreach (var id in WatcherId)
            {
                request.Data.Attributes.Watchers.Add(new YaraWatcher { Id = id, Type = "user" });
            }
        }
        using var client = VirusTotalClient.Create(ApiKey);
        var result = client.UpdateYaraRulesetAsync(Id, request).GetAwaiter().GetResult();
        if (result != null)
        {
            WriteObject(result);
        }
    }
}

