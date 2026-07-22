using System.Reflection;

// Feeds the compiled exe's Win32 version resource (Explorer's Properties >
// Details tab) so a file's version is visible without running it. Version
// numbers are pulled from Program.ProductVersion (a compile-time constant)
// instead of being duplicated here, so bumping that one value keeps both in
// sync automatically.
[assembly: AssemblyTitle("Windows Inventory Lite Client")]
[assembly: AssemblyDescription("Inventory collection agent for Windows Inventory Lite")]
[assembly: AssemblyProduct("Windows Inventory Lite")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyCopyright("didimozg")]
[assembly: AssemblyVersion(WindowsInventoryLite.Program.ProductVersion + ".0")]
[assembly: AssemblyFileVersion(WindowsInventoryLite.Program.ProductVersion + ".0")]
