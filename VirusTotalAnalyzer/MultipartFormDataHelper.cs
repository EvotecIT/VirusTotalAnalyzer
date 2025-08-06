using System;
using System.IO;
using System.Net.Http;

namespace VirusTotalAnalyzer;

internal static class MultipartFormDataHelper
{
    public static MultipartFormDataContent Create(Stream stream, string fileName)
    {
        var boundary = Guid.NewGuid().ToString("N");
        var content = new MultipartFormDataContent(boundary);
        var fileContent = new StreamContent(stream);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", fileName);
        return content;
    }
}
