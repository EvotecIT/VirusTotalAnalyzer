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

    public static IEnumerable<object[]> InvalidIdsOperations()
    {
        var idsWithNull = new[] { "valid", null };
        var idsWithEmpty = new[] { "valid", string.Empty };
        var idsWithWhitespace = new[] { "valid", "   " };

        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetFileReportsAsync(idsWithNull)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetUrlReportsAsync(idsWithNull)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetIpAddressReportsAsync(idsWithNull)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetDomainReportsAsync(idsWithNull)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetAnalysesAsync(idsWithNull)) };

        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetFileReportsAsync(idsWithEmpty)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetUrlReportsAsync(idsWithEmpty)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetIpAddressReportsAsync(idsWithEmpty)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetDomainReportsAsync(idsWithEmpty)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetAnalysesAsync(idsWithEmpty)) };

        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetFileReportsAsync(idsWithWhitespace)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetUrlReportsAsync(idsWithWhitespace)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetIpAddressReportsAsync(idsWithWhitespace)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetDomainReportsAsync(idsWithWhitespace)) };
        yield return new object[] { new Func<IVirusTotalClient, Task>(c => c.GetAnalysesAsync(idsWithWhitespace)) };
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

    [Theory]
    [MemberData(nameof(InvalidIdsOperations))]
    public async Task IdsParameter_InvalidEntries_Throws(Func<IVirusTotalClient, Task> operation)
    {
        var client = CreateClient();
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () => await operation(client));
        Assert.StartsWith("The collection cannot contain null, empty, or whitespace ids.", exception.Message);
    }
}
