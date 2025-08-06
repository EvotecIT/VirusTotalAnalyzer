using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MultipartFormDataBuilderTests
{
    [Fact]
    public async Task Build_ReturnsContentWithBoundary()
    {
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes("hi"));
        var builder = new MultipartFormDataBuilder(ms, "test.txt");
        using var content = builder.Build();

        var boundaryParam = content.Headers.ContentType!.Parameters.First(p => p.Name == "boundary");
        Assert.Equal(builder.Boundary, boundaryParam.Value);

        var bytes = await content.ReadAsByteArrayAsync();
        var expected = Encoding.UTF8.GetBytes(
            $"--{builder.Boundary}\r\n" +
            "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n" +
            "hi\r\n" +
            $"--{builder.Boundary}--\r\n");
        Assert.Equal(expected, bytes);
    }
}
