using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

/// <summary>
/// Converts Unix timestamp seconds to <see cref="DateTimeOffset"/> and back.
/// </summary>
public sealed class UnixTimestampConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException();
        }

        var seconds = reader.GetInt64();
        return DateTimeOffset.FromUnixTimeSeconds(seconds);
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.ToUnixTimeSeconds());
    }
}
