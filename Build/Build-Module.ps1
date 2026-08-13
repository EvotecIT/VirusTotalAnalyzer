param(
    [ValidateSet('Manifest', 'Documentation', 'Build', 'Publish')]
    [string] $ConfigurationGateMode = 'Build',

    [bool] $SignModule = $true,

    [string] $ProjectBuildConfigPath = '..\Build\project.build.json',

    [string] $PowerShellGalleryApiKeyPath = 'C:\Support\Important\PowerShellGalleryAPI.txt',

    [string] $GitHubApiKeyPath = 'C:\Support\Important\GitHubAPI.txt'
)

& (Join-Path $PSScriptRoot '..\Module\Build\Build-Module.ps1') @PSBoundParameters
exit $LASTEXITCODE
