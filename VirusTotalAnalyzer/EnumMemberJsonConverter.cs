using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer;

public sealed class EnumMemberJsonConverter : JsonConverterFactory
{
    private readonly JsonNamingPolicy? _namingPolicy;

    public EnumMemberJsonConverter(JsonNamingPolicy? namingPolicy = null)
        => _namingPolicy = namingPolicy;

    public override bool CanConvert(Type typeToConvert)
        => (Nullable.GetUnderlyingType(typeToConvert) ?? typeToConvert).IsEnum;

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        var enumType = Nullable.GetUnderlyingType(typeToConvert) ?? typeToConvert;
        var converterType = typeof(EnumMemberConverter<>).MakeGenericType(enumType);
        return (JsonConverter)Activator.CreateInstance(converterType, _namingPolicy)!;
    }

    private sealed class EnumMemberConverter<T> : JsonConverter<T> where T : struct, Enum
    {
        private readonly Dictionary<T, string> _toString;
        private readonly Dictionary<string, T> _fromString;

        public EnumMemberConverter(JsonNamingPolicy? namingPolicy)
        {
            _toString = new Dictionary<T, string>();
            _fromString = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);

            foreach (var value in Enum.GetValues(typeof(T)))
            {
                var name = value!.ToString()!;
                var field = typeof(T).GetField(name)!;
                var attr = field.GetCustomAttribute<EnumMemberAttribute>();
                var text = attr?.Value ?? namingPolicy?.ConvertName(name) ?? name;
                _toString[(T)value] = text;
                _fromString[text] = (T)value;
            }
        }

        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var text = reader.GetString() ?? throw new JsonException();
            if (_fromString.TryGetValue(text, out var value))
            {
                return value;
            }
            throw new JsonException($"Unknown value '{text}' for enum '{typeof(T)}'.");
        }

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
            => writer.WriteStringValue(_toString[value]);
    }
}

