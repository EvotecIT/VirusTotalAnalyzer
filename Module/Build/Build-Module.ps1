param(
    [ValidateSet('Manifest', 'Documentation', 'Build', 'Publish')]
    [string] $ConfigurationGateMode = 'Build',

    [bool] $SignModule = $true,

    [string] $ProjectBuildConfigPath = '..\Build\project.build.json',

    [string] $PowerShellGalleryApiKeyPath = 'C:\Support\Important\PowerShellGalleryAPI.txt',

    [string] $GitHubApiKeyPath = 'C:\Support\Important\GitHubAPI.txt'
)

Import-Module PSPublishModule -Force -ErrorAction Stop

Build-Module -ModuleName 'VirusTotalAnalyzer' {
    $Manifest = @{
        ModuleVersion        = '1.0.X'
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = '2e82faa1-d870-42b2-b5aa-4a63bf02f43e'
        Author               = 'Przemyslaw Klys'
        CompanyName          = 'Evotec'
        Copyright            = "(c) 2011 - $((Get-Date).Year) Przemyslaw Klys @ Evotec. All rights reserved."
        Description          = 'VirusTotal API v3 module for reports, submissions, community data, and publisher Monitor workflows.'
        PowerShellVersion    = '5.1'
        Tags                 = @('Windows', 'Linux', 'macOS', 'VirusTotal', 'Monitor', 'publisher', 'malware', 'security')
        ProjectUri           = 'https://github.com/EvotecIT/VirusTotalAnalyzer'
    }
    New-ConfigurationManifest @Manifest

    New-ConfigurationModule -Type ExternalModule -Name 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility'

    $ConfigurationFormat = @{
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
    New-ConfigurationFormat -ApplyTo 'OnMergePSM1', 'OnMergePSD1' -Sort None @ConfigurationFormat
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'DefaultPSM1' -EnableFormatting -Sort None
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'OnMergePSD1' -PSD1Style 'Minimal'

    New-ConfigurationDocumentation -Enable -PathReadme 'Docs\Readme.md' -Path 'Docs' -SyncExternalHelpToProjectRoot -ExternalHelpFileName 'VirusTotalAnalyzer.PowerShell.dll-Help.xml'
    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    $ModuleBuild = @{
        Enable                            = $true
        SignModule                        = $SignModule
        CertificateThumbprint             = '92E95FB58EFFA6A4A75E77A33CDD6BFE6DD30F1A'
        DeleteTargetModuleBeforeBuild     = $true
        MergeModuleOnBuild                = $true
        MergeFunctionsFromApprovedModules = $false
        DoNotAttemptToFixRelativePaths    = $true
        NETProjectPath                    = '..\VirusTotalAnalyzer.PowerShell\VirusTotalAnalyzer.PowerShell.csproj'
        NETProjectName                    = 'VirusTotalAnalyzer.PowerShell'
        NETBinaryModule                   = 'VirusTotalAnalyzer.PowerShell.dll'
        NETConfiguration                  = 'Release'
        NETFramework                      = 'net472', 'net8.0'
        NETSearchClass                    = 'VirusTotalAnalyzer.PowerShell.CmdletGetVirusReport'
        NETBinaryModuleDocumentation      = $true
    }
    New-ConfigurationBuild @ModuleBuild

    New-ConfigurationProjectBuild -Name 'VirusTotalAnalyzer' -ConfigPath $ProjectBuildConfigPath -Enabled -BuildBeforeModule -UseAsReleaseVersionSource -ProvideLocalNuGetFeed -PublishNuget
    New-ConfigurationRelease -StageRoot '..\Artefacts\UploadReady' -VersionSource ProjectBuild -PrimaryProject 'VirusTotalAnalyzer' -SynchronizeModuleVersion -PublishOrder 'NuGet', 'PowerShellGallery', 'GitHub'

    New-ConfigurationArtefact -Type Unpacked -Enable -Path '..\Artefacts\Unpacked' -ModulesPath '..\Artefacts\Unpacked\Modules'
    New-ConfigurationArtefact -Type Packed -Enable -Path '..\Artefacts\Packed' -ModulesPath '..\Artefacts\Packed\Modules' -IncludeTagName

    New-ConfigurationPublish -Type PowerShellGallery -FilePath $PowerShellGalleryApiKeyPath -Enabled:$false
    New-ConfigurationPublish -Type GitHub -FilePath $GitHubApiKeyPath -UserName 'EvotecIT' -RepositoryName 'VirusTotalAnalyzer' -Enabled:$false -GenerateReleaseNotes -OverwriteTagName '{ModuleName}-v{ModuleVersionWithPreRelease}'

    New-ConfigurationGate -Mode $ConfigurationGateMode
} -ExitCode
