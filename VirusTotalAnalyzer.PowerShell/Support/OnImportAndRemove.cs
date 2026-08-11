using System;
using System.IO;
using System.Management.Automation;
using System.Reflection;

/// <summary>
/// OnModuleImportAndRemove is a class that implements the IModuleAssemblyInitializer and IModuleAssemblyCleanup interfaces.
/// This class is used to handle the assembly resolve event when the module is imported and removed.
/// </summary>
public sealed class OnModuleImportAndRemove : IModuleAssemblyInitializer, IModuleAssemblyCleanup {
    /// <summary>
    /// OnImport is called when the module is imported.
    /// </summary>
    public void OnImport() {
        if (IsNetFramework()) {
            AppDomain.CurrentDomain.AssemblyResolve += MyResolveEventHandler;
        }
    }

    /// <summary>
    /// OnRemove is called when the module is removed.
    /// </summary>
    /// <param name="module"></param>
    public void OnRemove(PSModuleInfo module) {
        if (IsNetFramework()) {
            AppDomain.CurrentDomain.AssemblyResolve -= MyResolveEventHandler;
        }
    }

    /// <summary>
    /// MyResolveEventHandler is a method that handles the AssemblyResolve event.
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="args"></param>
    /// <returns></returns>
    private static Assembly? MyResolveEventHandler(object? sender, ResolveEventArgs args) {
        var assemblyLocation = typeof(OnModuleImportAndRemove).Assembly.Location;
        if (string.IsNullOrEmpty(assemblyLocation)) {
            return null;
        }

        var libDirectory = Path.GetDirectoryName(assemblyLocation);
        if (string.IsNullOrEmpty(libDirectory)) {
            return null;
        }

        var assemblyName = new AssemblyName(args.Name).Name;
        if (string.IsNullOrEmpty(assemblyName)) {
            return null;
        }
        var assemblyPath = Path.Combine(libDirectory, assemblyName + ".dll");
        if (File.Exists(assemblyPath)) {
            try {
                return Assembly.LoadFrom(assemblyPath);
            } catch (Exception ex) {
                Console.WriteLine($"Failed to load assembly from {assemblyPath}: {ex.Message}");
            }
        }

        return null;
    }

    /// <summary>
    /// Determine if the current runtime is .NET Framework
    /// </summary>
    /// <returns></returns>
    private bool IsNetFramework() {
        return System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription.StartsWith(".NET Framework", StringComparison.OrdinalIgnoreCase);
    }
}
