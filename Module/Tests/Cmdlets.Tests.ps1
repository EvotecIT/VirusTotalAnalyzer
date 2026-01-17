# Pester tests for compiled cmdlets

Describe 'VirusTotalAnalyzer cmdlets' {
BeforeAll {
    function Get-TestModulePaths {
        $configuration = $env:BUILD_CONFIGURATION
        if ([string]::IsNullOrWhiteSpace($configuration)) {
            $configuration = 'Release'
        }
        $targetFramework = $env:POWERSHELL_TFM
        if ([string]::IsNullOrWhiteSpace($targetFramework)) {
            $targetFramework = 'net8.0'
        }
        $binRoot = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'VirusTotalAnalyzer.PowerShell', 'bin', $configuration)
        if (-not (Test-Path $binRoot)) {
            $binRoot = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'VirusTotalAnalyzer.PowerShell', 'bin', 'Debug')
        }
        $binPath = [System.IO.Path]::Combine($binRoot, $targetFramework)
        if (-not (Test-Path $binPath)) {
            $binPath = Get-ChildItem -Path $binRoot -Directory | Where-Object { $_.Name -like 'net*' } | Select-Object -First 1 -ExpandProperty FullName
        }
        if (-not $binPath -or -not (Test-Path $binPath)) {
            throw "Unable to locate module build output under $binRoot."
        }
        [pscustomobject]@{
            BinPath = $binPath
            ModulePath = [System.IO.Path]::Combine($binPath, 'VirusTotalAnalyzer.PowerShell.dll')
            AssemblyPath = [System.IO.Path]::Combine($binPath, 'VirusTotalAnalyzer.dll')
        }
    }

    $paths = Get-TestModulePaths
    $script:modulePath = $paths.ModulePath
    $script:assemblyPath = $paths.AssemblyPath
    [Reflection.Assembly]::LoadFrom($script:assemblyPath) | Out-Null
    Import-Module $script:modulePath -Force

    Add-Type @"
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public class FakeHandler : HttpMessageHandler
{
    private readonly string _response;
    public HttpRequestMessage LastRequest { get; private set; }

    public FakeHandler(string response) => _response = response;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        var message = new HttpResponseMessage(HttpStatusCode.OK);
        message.Content = new StringContent(_response);
        return Task.FromResult(message);
    }
}
"@ | Out-Null
}

Describe 'Get-VirusReport cmdlet' {
    It 'retrieves a file report by hash' {
        $json = '{"data":{"id":"abc","type":"file"}}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $result = Get-VirusReport -ApiKey 'x' -Hash 'abc' -Client $client
        $result.Id | Should -Be 'abc'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc'
    }

    It 'uses lowercase hash when hashing file content' {
        $json = '{"data":{"id":"def","type":"file"}}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'
        $expected = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()

        Get-VirusReport -ApiKey 'x' -File $file -Client $client | Out-Null
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be "/api/v3/files/$expected"
    }

    It 'reports progress when hashing a file' {
        $json = '{"data":{"id":"ghi","type":"file"}}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'

        $ps = [powershell]::Create()
        try {
            $null = $ps.AddCommand('Import-Module').AddParameter('Name', $script:modulePath).AddParameter('Force', $true).AddParameter('ErrorAction', 'Stop').Invoke()
            $ps.Commands.Clear()
            $null = $ps.AddCommand('Get-VirusReport').AddParameter('ApiKey','x').AddParameter('File',$file).AddParameter('Client',$client).Invoke()
            $ps.Streams.Progress.Count | Should -BeGreaterThan 0
            $ps.Streams.Progress[-1].RecordType | Should -Be ([System.Management.Automation.ProgressRecordType]::Completed)
        }
        finally {
            $ps.Dispose()
        }
    }
}

Describe 'New-VirusScan cmdlet' {
    It 'submits a file for analysis' {
        $json = '{"id":"analysis1","type":"analysis"}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'

        $result = New-VirusScan -ApiKey 'x' -File $file -Client $client
        $result.Id | Should -Be 'analysis1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files'
    }

    It 'reanalyzes a file using a lowercase hash' {
        $json = '{"id":"analysis2","type":"analysis"}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'
        $expected = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()

        New-VirusScan -ApiKey 'x' -FileHash $file -Client $client | Out-Null
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be "/api/v3/files/$expected/analyse"
    }

    It 'reports progress when hashing a file for reanalysis' {
        $json = '{"id":"analysis3","type":"analysis"}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'

        $ps = [powershell]::Create()
        try {
            $null = $ps.AddCommand('Import-Module').AddParameter('Name', $script:modulePath).AddParameter('Force', $true).AddParameter('ErrorAction', 'Stop').Invoke()
            $ps.Commands.Clear()
            $null = $ps.AddCommand('New-VirusScan').AddParameter('ApiKey','x').AddParameter('FileHash',$file).AddParameter('Client',$client).Invoke()
            $ps.Streams.Progress.Count | Should -BeGreaterThan 0
            $ps.Streams.Progress[-1].RecordType | Should -Be ([System.Management.Automation.ProgressRecordType]::Completed)
        }
        finally {
            $ps.Dispose()
        }
    }
}

Describe 'Get-VirusComment cmdlet' {
    It 'retrieves comments for a resource' {
        $json = '{"data":[{"id":"c1","type":"comment"}]}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $result = @(Get-VirusComment -ApiKey 'x' -ResourceType File -Id 'abc' -Client $client)[0]
        $result.Id | Should -Be 'c1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc/comments'
    }
}

Describe 'New-VirusVote cmdlet' {
    It 'casts a vote for a resource' {
        $json = '{"data":{"id":"v1","type":"vote"}}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $result = New-VirusVote -ApiKey 'x' -ResourceType File -Id 'abc' -Verdict Malicious -Client $client
        $result.Id | Should -Be 'v1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc/votes'
    }
}

Describe 'Get-VirusUser cmdlet' {
    It 'retrieves user information' {
        $json = '{"id":"user1","type":"user"}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        $result = Get-VirusUser -ApiKey 'x' -Id 'user1' -Client $client
        $result.Id | Should -Be 'user1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/users/user1'
    }
}

Describe 'Cmdlet help content' {
    It 'includes examples for Get-VirusReport' {
        (Get-Help Get-VirusReport -Examples).Examples | Should -Not -BeNullOrEmpty
    }
    It 'includes examples for New-VirusScan' {
        (Get-Help New-VirusScan -Examples).Examples | Should -Not -BeNullOrEmpty
    }
    It 'includes examples for Get-VirusComment' {
        (Get-Help Get-VirusComment -Examples).Examples | Should -Not -BeNullOrEmpty
    }
    It 'includes examples for New-VirusVote' {
        (Get-Help New-VirusVote -Examples).Examples | Should -Not -BeNullOrEmpty
    }
    It 'includes examples for Get-VirusUser' {
        (Get-Help Get-VirusUser -Examples).Examples | Should -Not -BeNullOrEmpty
    }
}
}
