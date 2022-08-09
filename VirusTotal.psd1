@{
    AliasesToExport      = @()
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @()
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2022 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'Helper module for working with Virus Total'
    FunctionsToExport    = @('Get-VirusReport', 'Invoke-VirusScan')
    GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
    ModuleVersion        = '0.0.1'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            Tags       = @('Windows', 'Linux', 'macOs', 'VirusTotal')
            ProjectUri = 'https://github.com/EvotecIT/VirusTotal'
        }
    }
    RootModule           = 'VirusTotal.psm1'
}