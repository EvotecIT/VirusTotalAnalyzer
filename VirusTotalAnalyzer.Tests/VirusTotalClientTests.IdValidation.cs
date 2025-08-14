using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    public static IEnumerable<object[]> NullIdOperations()
    {
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetFileReportAsync(null!)) };
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetFileContactedUrlsAsync(null!)) };
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetCommentAsync(null!)) };
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetGraphAsync(null!)) };
    }

    public static IEnumerable<object[]> EmptyIdOperations()
    {
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetFileReportAsync(string.Empty)) };
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetFileContactedUrlsAsync(string.Empty)) };
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetCommentAsync(string.Empty)) };
        yield return new object[] { new Func<VirusTotalClient, Task>(c => c.GetGraphAsync(string.Empty)) };
    }

    [Theory]
    [MemberData(nameof(NullIdOperations))]
    public async Task IdParameter_Null_Throws(Func<VirusTotalClient, Task> operation)
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await operation(client));
    }

    [Theory]
    [MemberData(nameof(EmptyIdOperations))]
    public async Task IdParameter_Empty_Throws(Func<VirusTotalClient, Task> operation)
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(async () => await operation(client));
    }
}

