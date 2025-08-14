using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileNetworkTraffic
{
    public NetworkTrafficData Data { get; set; } = new();
}

public sealed class NetworkTrafficData
{
    public List<NetworkTcpEntry> Tcp { get; set; } = new();
}

public sealed class NetworkTcpEntry
{
    [JsonPropertyName("dst")]
    public string? Destination { get; set; }

    public int Port { get; set; }
}
