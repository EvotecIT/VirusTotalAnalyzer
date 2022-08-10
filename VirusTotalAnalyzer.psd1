@{
    AliasesToExport      = 'Get-VirusScan'
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @()
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2022 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'PowerShell module that intearacts with the VirusTotal service using a VirusTotal API (free)'
    FunctionsToExport    = @('Get-VirusReport', 'New-VirusScan')
    GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
    ModuleVersion        = '0.0.3'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            Tags       = @('Windows', 'Linux', 'macOs', 'VirusTotal', 'virus', 'threat', 'analyzer')
            ProjectUri = 'https://github.com/EvotecIT/VirusTotalAnalyzer'
        }
    }
    RootModule           = 'VirusTotalAnalyzer.psm1'
}