@{
    AliasesToExport      = @('Get-VirusScan')
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Get-VirusReport', 'New-VirusScan')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2025 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'PowerShell module that intearacts with the VirusTotal service using a VirusTotal API (free)'
    FunctionsToExport    = @()
    GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
    ModuleVersion        = '0.0.5'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility')
            ProjectUri                 = 'https://github.com/EvotecIT/VirusTotalAnalyzer'
            Tags                       = @('Windows', 'Linux', 'macOs', 'VirusTotal', 'virus', 'threat', 'analyzer')
        }
    }
    RequiredModules      = @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility')
    RootModule           = 'VirusTotalAnalyzer.PowerShell.dll'
}