# Pester tests for compiled cmdlets

$binPath = Join-Path $PSScriptRoot '..' '..' 'VirusTotalAnalyzer.PowerShell' 'bin' 'Debug' 'net8.0'
[Reflection.Assembly]::LoadFrom((Join-Path $binPath 'VirusTotalAnalyzer.dll')) | Out-Null
Import-Module (Join-Path $binPath 'VirusTotalAnalyzer.PowerShell.dll')

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

    It 'maps First and Skip to search limit and cursor' {
        $json = '{"data":[]}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        Get-VirusReport -ApiKey 'x' -Search 'demo query' -Client $client -First 10 -Skip 3 | Out-Null
        $handler.LastRequest.RequestUri.AbsolutePath | Should -Be '/api/v3/intelligence/search'
        $handler.LastRequest.RequestUri.Query | Should -Be '?query=demo%20query&limit=10&cursor=3'
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

    It 'supports paging with First and Skip' {
        $json = '{"data":[{"id":"c1","type":"comment"}]}'
        $handler = [FakeHandler]::new($json)
        $httpClient = [System.Net.Http.HttpClient]::new($handler)
        $httpClient.BaseAddress = [Uri]::new('https://www.virustotal.com/api/v3/')
        $client = [VirusTotalAnalyzer.VirusTotalClient]::new($httpClient)

        Get-VirusComment -ApiKey 'x' -ResourceType File -Id 'abc' -Client $client -First 10 -Skip 5 | Out-Null
        $handler.LastRequest.RequestUri.Query | Should -Be '?limit=10&cursor=5'
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
