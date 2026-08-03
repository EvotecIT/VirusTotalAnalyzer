@{
    AliasesToExport      = @('Get-VirusScan')
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Get-VirusComment', 'Get-VirusReport', 'Get-VirusUser', 'New-VirusScan', 'New-VirusVote')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2026 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'PowerShell module that intearacts with the VirusTotal service using a VirusTotal API (free)'
    FunctionsToExport    = @()
    GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
    ModuleVersion        = '0.0.6'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @()
            ProjectUri                 = 'https://github.com/EvotecIT/VirusTotalAnalyzer'
            Tags                       = @('Windows', 'Linux', 'macOs', 'VirusTotal', 'virus', 'threat', 'analyzer')
            RequireLicenseAcceptance   = $false
        }
    }
    RequiredModules      = @(@{
            Guid            = 'ee272aa8-baaa-4edf-9f45-b6d6f7d844fe'
            ModuleName      = 'PSSharedGoods'
            ModuleVersion   = '0.0.313.1'
        })
    RootModule           = 'VirusTotalAnalyzer.psm1'
    ScriptsToProcess     = @()
}