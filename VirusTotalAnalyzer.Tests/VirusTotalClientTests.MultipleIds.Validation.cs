using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    public static IEnumerable<object[]> EmptyIdsOperations()
    {
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetFileReportsAsync(Array.Empty<string>())) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetUrlReportsAsync(Array.Empty<string>())) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetIpAddressReportsAsync(Array.Empty<string>())) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetDomainReportsAsync(Array.Empty<string>())) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetAnalysesAsync(Array.Empty<string>())) };
    }

    public static IEnumerable<object[]> TooManyIdsOperations()
    {
        var ids = new[] { "a", "b", "c", "d", "e" };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetFileReportsAsync(ids)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetUrlReportsAsync(ids)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetIpAddressReportsAsync(ids)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetDomainReportsAsync(ids)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetAnalysesAsync(ids)) };
    }

    [Theory]
    [MemberData(nameof(EmptyIdsOperations))]
    public async Task IdsParameter_Empty_Throws(Func<IVirusTotalClient, Task> operation)
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(async () => await operation(client));
    }

    [Theory]
    [MemberData(nameof(TooManyIdsOperations))]
    public async Task IdsParameter_TooMany_Throws(Func<IVirusTotalClient, Task> operation)
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(async () => await operation(client));
    }
}
