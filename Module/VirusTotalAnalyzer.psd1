@{
    AliasesToExport      = @('Get-VirusAccount', 'Get-VirusScan')
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Get-VirusComment', 'Get-VirusRelationship', 'Get-VirusReport', 'Get-VirusTotalMonitorEvent', 'Get-VirusTotalMonitorItem', 'Get-VirusTotalMonitorStatistics', 'Get-VirusUser', 'New-VirusScan', 'New-VirusTotalMonitorFolder', 'New-VirusVote', 'Remove-VirusTotalMonitorItem', 'Send-VirusTotalMonitorFile', 'Set-VirusTotalMonitorItem')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2026 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'VirusTotal API v3 module for reports, submissions, community data, and publisher Monitor workflows.'
    FunctionsToExport    = @()
    GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
    ModuleVersion        = '1.0.0'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @()
            ProjectUri                 = 'https://github.com/EvotecIT/VirusTotalAnalyzer'
            Tags                       = @('Windows', 'Linux', 'macOS', 'VirusTotal', 'Monitor', 'publisher', 'malware', 'security')
            RequireLicenseAcceptance   = $false
        }
    }
    RequiredModules      = @()
    RootModule           = 'VirusTotalAnalyzer.psm1'
    ScriptsToProcess     = @()
}