using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Gets one Monitor item or lists publisher Monitor items.</summary>
/// <example>
///   <summary>Get one Monitor item by identifier.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusTotalMonitorItem -ApiKey $ApiKey -Id 'monitor-item-id'</para>
///   </code>
/// </example>
/// <example>
///   <summary>List items below an absolute Monitor path.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>$page = Get-VirusTotalMonitorItem -ApiKey $ApiKey -List -Path '/releases/'</para>
///   </code>
///   <para>List mode returns the full page unless All is specified, preserving its continuation cursor.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "VirusTotalMonitorItem", DefaultParameterSetName = "ById")]
[OutputType(typeof(MonitorItem), typeof(PagedResponse<MonitorItem>))]
public sealed class CmdletGetVirusTotalMonitorItem : VirusTotalCmdlet
{
    /// <summary>Monitor item identifier.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ById", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string? Id { get; set; }

    /// <summary>Selects list mode instead of retrieving one item.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "List")]
    public SwitchParameter List { get; set; }

    /// <summary>Optional VirusTotal Monitor item filter expression.</summary>
    [Parameter(ParameterSetName = "List")]
    public string? Filter { get; set; }

    /// <summary>Lists items below this absolute Monitor path.</summary>
    [Parameter(ParameterSetName = "List")]
    public string? Path { get; set; }

    /// <summary>Lists children of this Monitor folder item.</summary>
    [Parameter(ParameterSetName = "List")]
    public string? ParentItemId { get; set; }

    /// <summary>Lists items matching one or more Monitor tags.</summary>
    [Parameter(ParameterSetName = "List")]
    public string[]? Tag { get; set; }

    /// <summary>Maximum number of items requested per page.</summary>
    [Parameter(ParameterSetName = "List")]
    [ValidateRange(1, int.MaxValue)]
    public int? Limit { get; set; }

    /// <summary>Cursor at which to begin listing.</summary>
    [Parameter(ParameterSetName = "List")]
    public string? Cursor { get; set; }

    /// <summary>Reads every page until VirusTotal returns no cursor.</summary>
    [Parameter(ParameterSetName = "List")]
    public SwitchParameter All { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            if (ParameterSetName == "ById")
            {
                WriteObject(await ActiveClient.GetMonitorItemAsync(Id!, CancelToken).ConfigureAwait(false));
                return;
            }

            var selectedFilters = (string.IsNullOrWhiteSpace(Filter) ? 0 : 1) +
                (string.IsNullOrWhiteSpace(Path) ? 0 : 1) +
                (string.IsNullOrWhiteSpace(ParentItemId) ? 0 : 1) +
                (Tag is null ? 0 : 1);
            if (selectedFilters > 1)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSArgumentException("Specify only one of Filter, Path, ParentItemId, or Tag."),
                    "AmbiguousMonitorItemFilter",
                    ErrorCategory.InvalidArgument,
                    null));
            }

            var effectiveFilter = !string.IsNullOrWhiteSpace(Path)
                ? MonitorItemFilter.ByPath(Path!).Expression
                : !string.IsNullOrWhiteSpace(ParentItemId)
                    ? MonitorItemFilter.ByItem(ParentItemId!).Expression
                    : Tag is not null
                        ? MonitorItemFilter.ByTags(Tag).Expression
                        : Filter;

            if (All)
            {
                await foreach (var item in ActiveClient.EnumerateMonitorItemsAsync(effectiveFilter, Limit, Cursor, CancelToken))
                {
                    WriteObject(item);
                }
                return;
            }

            var page = await ActiveClient.ListMonitorItemsAsync(effectiveFilter, Limit, Cursor, CancelToken).ConfigureAwait(false);
            if (page is not null)
            {
                WriteObject(page);
            }
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, Id ?? Filter ?? Path ?? ParentItemId);
        }
    }
}
