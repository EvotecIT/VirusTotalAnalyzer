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

    Add-Type -ReferencedAssemblies 'System.Net.Http','System.Net.Primitives','System.Collections','System.Collections.NonGeneric' @"
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public class FakeHandler : HttpMessageHandler
{
    private readonly string _response;
    public HttpRequestMessage LastRequest { get; private set; }

    public FakeHandler(string response)
    {
        _response = response;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        var message = new HttpResponseMessage(HttpStatusCode.OK);
        message.Content = new StringContent(_response);
        return Task.FromResult(message);
    }
}

public class QueueFakeHandler : HttpMessageHandler
{
    private readonly System.Collections.Queue _responses;
    public System.Collections.ArrayList Requests { get; private set; }

    public QueueFakeHandler(params string[] responses)
    {
        _responses = new System.Collections.Queue(responses);
        Requests = new System.Collections.ArrayList();
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        var response = _responses.Count > 0 ? (string)_responses.Dequeue() : "{}";
        var message = new HttpResponseMessage(HttpStatusCode.OK);
        message.Content = new StringContent(response);
        return Task.FromResult(message);
    }
}

public class StatusQueueFakeHandler : HttpMessageHandler
{
    private readonly System.Collections.Queue _responses;
    private readonly System.Collections.Queue _statusCodes;
    public System.Collections.ArrayList Requests { get; private set; }

    public StatusQueueFakeHandler(string[] responses, int[] statusCodes)
    {
        _responses = new System.Collections.Queue(responses);
        _statusCodes = new System.Collections.Queue(statusCodes);
        Requests = new System.Collections.ArrayList();
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        var response = _responses.Count > 0 ? (string)_responses.Dequeue() : "{}";
        var statusCode = _statusCodes.Count > 0 ? (int)_statusCodes.Dequeue() : 200;
        var message = new HttpResponseMessage((HttpStatusCode)statusCode);
        message.Content = new StringContent(response);
        return Task.FromResult(message);
    }
}
"@ | Out-Null

    function New-TestVirusTotalClient {
        param([FakeHandler] $ApiHandler)

        $downloadHandler = [FakeHandler]::new('{}')
        [VirusTotalAnalyzer.VirusTotalClient]::new('test-api-key', $ApiHandler, $downloadHandler)
    }
}

Describe 'Get-VirusReport cmdlet' {
    It 'retrieves a file report by hash' {
        $json = '{"data":{"id":"abc","type":"file"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $result = Get-VirusReport -Hash 'abc' -Client $client
        $result.Id | Should -Be 'abc'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc'
    }

    It 'uses lowercase hash when hashing file content' {
        $json = '{"data":{"id":"def","type":"file"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'
        $expected = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()

        Get-VirusReport -File $file -Client $client | Out-Null
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be "/api/v3/files/$expected"
    }

    It 'reports progress when hashing a file' {
        $json = '{"data":{"id":"ghi","type":"file"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'

        $ps = [powershell]::Create()
        try {
            $null = $ps.AddCommand('Import-Module').AddParameter('Name', $script:modulePath).AddParameter('Force', $true).AddParameter('ErrorAction', 'Stop').Invoke()
            $ps.Commands.Clear()
            $null = $ps.AddCommand('Get-VirusReport').AddParameter('File',$file).AddParameter('Client',$client).Invoke()
            $ps.Streams.Progress.Count | Should -BeGreaterThan 0
            $ps.Streams.Progress[-1].RecordType | Should -Be ([System.Management.Automation.ProgressRecordType]::Completed)
        }
        finally {
            $ps.Dispose()
        }
    }

    It 'deduplicates a report batch and can return concise verdicts' {
        $handler = [QueueFakeHandler]::new([string[]] @(
            '{"data":{"id":"abc","type":"file","attributes":{"reputation":-2,"last_analysis_stats":{"malicious":1,"harmless":4}}}}'
        ))
        $downloadHandler = [FakeHandler]::new('{}')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new('test-api-key', $handler, $downloadHandler)

        $result = @(Get-VirusReport -Hash 'abc','ABC' -Client $client -Summary -MinimumIntervalSeconds 0)

        $result.Count | Should -Be 2
        $result[0].Verdict.ToString() | Should -Be 'Malicious'
        $result[0].Report.Id | Should -Be 'abc'
        $handler.Requests.Count | Should -Be 1
    }

    It 'accepts hash objects from the pipeline by property name' {
        $handler = [QueueFakeHandler]::new([string[]] @(
            '{"data":{"id":"abc","type":"file","attributes":{}}}'
        ))
        $downloadHandler = [FakeHandler]::new('{}')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new('test-api-key', $handler, $downloadHandler)

        $result = @([pscustomobject] @{ Hash = 'abc' }, [pscustomobject] @{ Hash = 'ABC' }) |
            Get-VirusReport -Client $client -MinimumIntervalSeconds 0

        @($result).Count | Should -Be 2
        $handler.Requests.Count | Should -Be 1
        $handler.Requests[0].RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc'
    }

    It 'preserves successful reports when another batch item fails' {
        $handler = [StatusQueueFakeHandler]::new(
            [string[]] @(
                '{"data":{"id":"first","type":"file","attributes":{}}}',
                '{"error":{"code":"NotFoundError","message":"missing"}}',
                '{"data":{"id":"third","type":"file","attributes":{}}}'
            ),
            [int[]] @(200, 404, 200))
        $downloadHandler = [FakeHandler]::new('{}')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new('test-api-key', $handler, $downloadHandler)
        $errors = @()

        $result = @(Get-VirusReport -Hash 'first','missing','third' -Client $client `
            -MinimumIntervalSeconds 0 -MaxRetries 0 -ErrorAction SilentlyContinue -ErrorVariable +errors)

        $result.Id | Should -Be @('first', 'third')
        $errors.Count | Should -Be 1
        $errors[0].TargetObject | Should -Be 'missing'
        $handler.Requests.Count | Should -Be 3
    }
}

Describe 'New-VirusScan cmdlet' {
    It 'submits a file for analysis' {
        $json = '{"data":{"id":"analysis1","type":"analysis"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'

        $result = New-VirusScan -File $file -Client $client
        $result.Id | Should -Be 'analysis1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files'
    }

    It 'reanalyzes a file using a lowercase hash' {
        $json = '{"data":{"id":"analysis2","type":"analysis"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'
        $expected = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()

        New-VirusScan -FileHash $file -Client $client | Out-Null
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be "/api/v3/files/$expected/analyse"
    }

    It 'reports progress when hashing a file for reanalysis' {
        $json = '{"data":{"id":"analysis3","type":"analysis"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $file = New-TemporaryFile
        Set-Content -Path $file -Value 'test'

        $ps = [powershell]::Create()
        try {
            $null = $ps.AddCommand('Import-Module').AddParameter('Name', $script:modulePath).AddParameter('Force', $true).AddParameter('ErrorAction', 'Stop').Invoke()
            $ps.Commands.Clear()
            $null = $ps.AddCommand('New-VirusScan').AddParameter('FileHash',$file).AddParameter('Client',$client).Invoke()
            $ps.Streams.Progress.Count | Should -BeGreaterThan 0
            $ps.Streams.Progress[-1].RecordType | Should -Be ([System.Management.Automation.ProgressRecordType]::Completed)
        }
        finally {
            $ps.Dispose()
        }
    }

    It 'can submit and return the completed analysis in one command' {
        $handler = [QueueFakeHandler]::new([string[]] @(
            '{"data":{"id":"analysis4","type":"analysis","attributes":{"status":"queued"}}}',
            '{"data":{"id":"analysis4","type":"analysis","attributes":{"status":"completed"}}}'
        ))
        $downloadHandler = [FakeHandler]::new('{}')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new('test-api-key', $handler, $downloadHandler)

        $result = New-VirusScan -Url 'https://example.com' -Client $client -Wait -TimeoutSeconds 5 -PollingIntervalSeconds 1

        $result.Id | Should -Be 'analysis4'
        $result.Attributes.Status.ToString() | Should -Be 'Completed'
        $handler.Requests.Count | Should -Be 2
        $handler.Requests[1].RequestUri.AbsolutePath | Should -Be '/api/v3/analyses/analysis4'
    }
}

Describe 'Get-VirusComment cmdlet' {
    It 'retrieves comments for a resource' {
        $json = '{"data":[{"id":"c1","type":"comment"}]}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $result = @(Get-VirusComment -ResourceType File -Id 'abc' -Client $client)[0]
        $result.Id | Should -Be 'c1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc/comments'
    }
}

Describe 'New-VirusVote cmdlet' {
    It 'casts a vote for a resource' {
        $json = '{"data":{"id":"v1","type":"vote"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $result = New-VirusVote -ResourceType File -Id 'abc' -Verdict Malicious -Client $client
        $result.Id | Should -Be 'v1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/files/abc/votes'
    }
}

Describe 'Get-VirusUser cmdlet' {
    It 'retrieves user information' {
        $json = '{"data":{"id":"user1","type":"user"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $result = Get-VirusUser -Id 'user1' -Client $client
        $result.Id | Should -Be 'user1'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/users/user1'
    }

    It 'uses VIRUSTOTAL_USER_ID without putting the API key in the route' {
        $json = '{"data":{"id":"user2","type":"user"}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler
        $previous = $env:VIRUSTOTAL_USER_ID
        try {
            $env:VIRUSTOTAL_USER_ID = 'user2'
            $result = Get-VirusAccount -Client $client

            $result.Id | Should -Be 'user2'
            $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/users/user2'
            $handler.LastRequest.RequestUri.AbsolutePath | Should -Not -Match 'test-api-key'
        }
        finally {
            $env:VIRUSTOTAL_USER_ID = $previous
        }
    }

    It 'returns quota rows with remaining usage' {
        $json = '{"data":{"id":"user1","type":"user","attributes":{"quotas":{"api_requests_daily":{"allowed":500,"used":25}}}}}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $quota = Get-VirusUser -Id 'user1' -Client $client -Quota

        $quota.Name | Should -Be 'api_requests_daily'
        $quota.Remaining | Should -Be 475
        $quota.PercentUsed | Should -Be 5
    }
}

Describe 'Get-VirusRelationship cmdlet' {
    It 'returns typed historical WHOIS records' {
        $json = '{"data":[{"id":"w1","type":"whois","attributes":{"registrar_name":"Example Registrar"}}]}'
        $handler = [FakeHandler]::new($json)
        $client = New-TestVirusTotalClient -ApiHandler $handler

        $result = Get-VirusRelationship -DomainName 'example.com' -Relationship HistoricalWhois -Client $client

        $result.Type.ToString() | Should -Be 'Whois'
        $result.Attributes.RegistrarName | Should -Be 'Example Registrar'
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/domains/example.com/historical_whois'
    }
}

Describe 'Send-VirusTotalMonitorFile cmdlet' {
    It 'honors WhatIf when replacing an existing Monitor item' {
        $handler = [FakeHandler]::new('{"data":{"id":"m1","type":"monitor_item"}}')
        $client = New-TestVirusTotalClient -ApiHandler $handler
        $file = New-TemporaryFile

        try {
            $result = Send-VirusTotalMonitorFile -File $file -ExistingItemId 'm1' -Client $client -WhatIf

            $result | Should -BeNullOrEmpty
            $handler.LastRequest | Should -BeNullOrEmpty
            (Get-Command Send-VirusTotalMonitorFile).Parameters.ContainsKey('WhatIf') | Should -BeTrue
        }
        finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Cmdlet parameter contracts' {
    It 'requires a report selector in every Get-VirusReport parameter set' {
        $command = Get-Command Get-VirusReport
        $selectors = 'AnalysisId', 'DomainName', 'File', 'Hash', 'IPAddress', 'Search', 'Url'

        foreach ($selector in $selectors) {
            $mandatory = @($command.Parameters[$selector].Attributes | Where-Object Mandatory)
            $mandatory.Count | Should -BeGreaterThan 0
        }
    }

    It 'requires an operation selector in every New-VirusScan parameter set' {
        $command = Get-Command New-VirusScan
        $selectors = 'File', 'FileHash', 'Hash', 'Url'

        foreach ($selector in $selectors) {
            $mandatory = @($command.Parameters[$selector].Attributes | Where-Object Mandatory)
            $mandatory.Count | Should -BeGreaterThan 0
        }
    }

    It 'keeps authentication optional for environment-key discovery' {
        $command = Get-Command Get-VirusReport
        @($command.Parameters.ApiKey.Attributes | Where-Object Mandatory).Count | Should -Be 0
        @($command.Parameters.Client.Attributes | Where-Object Mandatory).Count | Should -Be 0
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
    It 'includes examples for Get-VirusRelationship' {
        (Get-Help Get-VirusRelationship -Examples).Examples | Should -Not -BeNullOrEmpty
    }
}
}
