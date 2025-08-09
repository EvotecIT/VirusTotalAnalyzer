using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileNetworkTraffic
{
    [JsonPropertyName("data")]
    public NetworkTrafficData Data { get; set; } = new();
}

public sealed class NetworkTrafficData
{
    [JsonPropertyName("tcp")]
    public List<NetworkTcpEntry> Tcp { get; set; } = new();
}

public sealed class NetworkTcpEntry
{
    [JsonPropertyName("dst")]
    public string? Destination { get; set; }

    [JsonPropertyName("port")]
    public int Port { get; set; }
}
