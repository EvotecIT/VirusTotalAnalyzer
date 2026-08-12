param(
    [ValidateSet('Manifest', 'Build', 'Publish', 'Documentation')]
    [string] $ConfigurationGateMode = 'Build'
)

Import-Module PSPublishModule -Force -ErrorAction Stop

Build-Module -ModuleName 'VirusTotalAnalyzer' {
    # Usual defaults as per standard module
    $Manifest = [ordered] @{
        # Version number of this module.
        ModuleVersion        = '0.0.X'
        # Supported PSEditions
        CompatiblePSEditions = @('Desktop', 'Core')
        # ID used to uniquely identify this module
        GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
        # Author of this module
        Author               = 'Przemyslaw Klys'
        # Company or vendor of this module
        CompanyName          = 'Evotec'
        # Copyright statement for this module
        Copyright            = "(c) 2011 - $((Get-Date).Year) Przemyslaw Klys @ Evotec. All rights reserved."
        # Description of the functionality provided by this module
        Description          = 'VirusTotal API v3 module for reports, submissions, community data, and publisher Monitor workflows.'
        # Minimum version of the Windows PowerShell engine required by this module
        PowerShellVersion    = '5.1'
        # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
        # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
        Tags                 = @('Windows', 'Linux', 'macOS', 'VirusTotal', 'Monitor', 'publisher', 'malware', 'security')

        ProjectUri           = 'https://github.com/EvotecIT/VirusTotalAnalyzer'
    }
    New-ConfigurationManifest @Manifest

    # Only built-in PowerShell modules are used by the generated bootstrapper.
    New-ConfigurationModule -Type ExternalModule -Name 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility'

    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $true
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # format PSD1 and PSM1 files when merging into a single file
    # enable formatting is not required as Configuration is provided
    New-ConfigurationFormat -ApplyTo 'OnMergePSM1', 'OnMergePSD1' -Sort None @ConfigurationFormat
    # format PSD1 and PSM1 files within the module
    # enable formatting is required to make sure that formatting is applied (with default settings)
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'DefaultPSM1' -EnableFormatting -Sort None
    # when creating PSD1 use special style without comments and with only required parameters
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'OnMergePSD1' -PSD1Style 'Minimal'

    # configuration for documentation, at the same time it enables documentation processing
    New-ConfigurationDocumentation -Enable -PathReadme 'Docs\Readme.md' -Path 'Docs' -SyncExternalHelpToProjectRoot -ExternalHelpFileName 'VirusTotalAnalyzer.PowerShell.dll-Help.xml'

    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    $newConfigurationBuildSplat = @{
        Enable                            = $true
        SignModule                        = if ([string]::IsNullOrWhiteSpace($Env:SignModule)) { $true } else { [bool]::Parse($Env:SignModule) }
        CertificateThumbprint             = '483292C9E317AA13B07BB7A96AE9D1A5ED9E7703'
        DeleteTargetModuleBeforeBuild     = $true
        MergeModuleOnBuild                = $true
        MergeFunctionsFromApprovedModules = $false
        DoNotAttemptToFixRelativePaths    = $true
        NETProjectPath                    = "$PSScriptRoot\..\..\VirusTotalAnalyzer.PowerShell"
        NETProjectName                    = 'VirusTotalAnalyzer.PowerShell'
        NETBinaryModule                   = 'VirusTotalAnalyzer.PowerShell.dll'
        NETConfiguration                  = 'Release'
        NETFramework                      = 'net472', 'net8.0'
        NETSearchClass                    = 'VirusTotalAnalyzer.PowerShell.CmdletGetVirusReport'
        NETBinaryModuleDocumentation      = $true
        RefreshPSD1Only                   = if ([string]::IsNullOrWhiteSpace($Env:RefreshPSD1Only)) { $false } else { [bool]::Parse($Env:RefreshPSD1Only) }
    }

    New-ConfigurationBuild @newConfigurationBuildSplat

    New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artefacts\Unpacked" -AddRequiredModules -RequiredModulesPath "$PSScriptRoot\..\Artefacts\Unpacked\Modules" -CopyFiles @{

    } -CopyFilesRelative

    New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artefacts\Packed" -AddRequiredModules -RequiredModulesPath "$PSScriptRoot\..\Artefacts\Packed\Modules" -CopyFiles @{

    } -CopyFilesRelative -IncludeTagName

    # global options for publishing to github/psgallery
    #New-ConfigurationPublish -Type PowerShellGallery -FilePath 'C:\Support\Important\PowerShellGalleryAPI.txt' -Enabled:$true
    #New-ConfigurationPublish -Type GitHub -FilePath 'C:\Support\Important\GitHubAPI.txt' -UserName 'EvotecIT' -Enabled:$true
} -RunMode $ConfigurationGateMode -NoInteractive
