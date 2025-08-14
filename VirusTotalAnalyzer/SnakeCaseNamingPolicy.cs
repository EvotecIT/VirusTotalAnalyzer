using System.Text;
using System.Text.Json;

namespace VirusTotalAnalyzer;

/// <summary>
/// <see cref="JsonNamingPolicy"/> that converts property names to snake_case.
/// </summary>
public sealed class SnakeCaseNamingPolicy : JsonNamingPolicy
{
    /// <summary>Shared instance of the naming policy.</summary>
    public static SnakeCaseNamingPolicy Instance { get; } = new();

    /// <inheritdoc />
    public override string ConvertName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return name;
        }

        var builder = new StringBuilder(name.Length + 10);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                if (i > 0 && (!char.IsUpper(name[i - 1]) || (i + 1 < name.Length && !char.IsUpper(name[i + 1]))))
                {
                    builder.Append('_');
                }
                builder.Append(char.ToLowerInvariant(c));
            }
            else
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }
}
