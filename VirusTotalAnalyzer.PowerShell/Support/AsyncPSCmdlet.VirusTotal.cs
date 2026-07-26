using System;
using System.IO;
using System.Management.Automation;
using System.Text;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

public abstract partial class AsyncPSCmdlet {
    /// <summary>Returns the effective error action preference.</summary>
    protected ActionPreference GetErrorActionPreference() {
        ActionPreference preference =
            (ActionPreference)SessionState.PSVariable.GetValue("ErrorActionPreference");
        if (MyInvocation.BoundParameters.ContainsKey("ErrorAction")) {
            string? errorActionString = MyInvocation.BoundParameters["ErrorAction"]?.ToString();
            if (!string.IsNullOrWhiteSpace(errorActionString) &&
                Enum.TryParse(errorActionString, true, out ActionPreference parsed)) {
                preference = parsed;
            }
        }

        return preference;
    }

    /// <summary>Verifies that the specified file exists.</summary>
    protected bool EnsureFileExists(string path, ActionPreference errorAction) {
        if (File.Exists(path)) {
            return true;
        }

        string message = $"{MyInvocation.InvocationName} - The specified file does not exist: {path}";
        if (errorAction == ActionPreference.Stop) {
            FileNotFoundException exception = new("The specified file does not exist.", path);
            ThrowTerminatingError(
                new ErrorRecord(
                    exception,
                    "FileNotFound",
                    ErrorCategory.ObjectNotFound,
                    path));
        } else {
            WriteWarning(message);
        }

        return false;
    }

    /// <summary>Writes a standardized VirusTotal API error.</summary>
    protected void WriteApiError(ApiException exception, object? targetObject = null) {
        if (exception is null) {
            throw new ArgumentNullException(nameof(exception));
        }

        string errorId = exception.Error?.Code ?? "VirusTotalApiError";
        ErrorRecord record = new(
            exception,
            errorId,
            ErrorCategory.InvalidOperation,
            targetObject);

        StringBuilder details = new();
        if (exception.StatusCode.HasValue) {
            details.Append($"StatusCode: {(int)exception.StatusCode.Value} ({exception.StatusCode})");
        }
        if (!string.IsNullOrWhiteSpace(exception.RequestId)) {
            if (details.Length > 0) {
                details.AppendLine();
            }
            details.Append($"RequestId: {exception.RequestId}");
        }
        if (details.Length > 0) {
            record.ErrorDetails = new ErrorDetails(details.ToString());
        }

        WriteError(record);
    }
}
