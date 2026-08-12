using System;
using System.Collections.Generic;
using System.Linq;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

/// <summary>Provides convenient views over VirusTotal account data.</summary>
public static class VirusTotalUserExtensions
{
    /// <summary>Returns the user's visible quotas as pipeline-friendly rows.</summary>
    public static IReadOnlyList<VirusTotalQuotaStatus> GetQuotaStatus(this User user)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        return user.Attributes.Quotas
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => new VirusTotalQuotaStatus
            {
                Name = pair.Key,
                Allowed = pair.Value.Allowed,
                Used = pair.Value.Used
            })
            .ToArray();
    }
}
