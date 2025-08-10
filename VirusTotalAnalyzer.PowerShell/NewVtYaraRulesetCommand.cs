using System.Collections.Generic;
using System.Management.Automation;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

[Cmdlet(VerbsCommon.New, "VtYaraRuleset")]
[OutputType(typeof(YaraRuleset))]
public sealed class NewVtYaraRulesetCommand : PSCmdlet
{
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    [Parameter(Mandatory = true)]
    public string Name { get; set; } = string.Empty;

    [Parameter(Mandatory = true)]
    public string Rules { get; set; } = string.Empty;

    [Parameter]
    public string[]? WatcherId { get; set; }

    protected override void ProcessRecord()
    {
        var request = new YaraRulesetRequest();
        request.Data.Attributes.Name = Name;
        request.Data.Attributes.Rules = Rules;
        if (WatcherId != null && WatcherId.Length > 0)
        {
            request.Data.Attributes.Watchers = new List<YaraWatcher>();
            foreach (var id in WatcherId)
            {
                request.Data.Attributes.Watchers.Add(new YaraWatcher { Id = id, Type = "user" });
            }
        }
        using var client = VirusTotalClient.Create(ApiKey);
        var result = client.CreateYaraRulesetAsync(request).GetAwaiter().GetResult();
        if (result != null)
        {
            WriteObject(result);
        }
    }
}

