using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer;

internal sealed class JsonStringEnumMemberConverter : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) => typeToConvert.IsEnum;

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
        => (JsonConverter)Activator.CreateInstance(typeof(EnumMemberConverter<>).MakeGenericType(typeToConvert))!;

    private sealed class EnumMemberConverter<T> : JsonConverter<T> where T : struct, Enum
    {
        private static readonly Dictionary<T, string> _toString;
        private static readonly Dictionary<string, T> _fromString;

        static EnumMemberConverter()
        {
            _toString = new Dictionary<T, string>();
            _fromString = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
            foreach (var field in typeof(T).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var value = (T)field.GetValue(null)!;
                var enumMember = field.GetCustomAttribute<EnumMemberAttribute>();
                var name = enumMember?.Value ?? field.Name;
                _toString[value] = name;
                _fromString[name] = value;
            }
        }

        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var str = reader.GetString();
            if (str != null && _fromString.TryGetValue(str, out var value))
            {
                return value;
            }
            throw new JsonException($"Unknown value '{str}' for enum '{typeof(T)}'.");
        }

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
        {
            if (_toString.TryGetValue(value, out var name))
            {
                writer.WriteStringValue(name);
                return;
            }
            writer.WriteStringValue(value.ToString());
        }
    }
}
