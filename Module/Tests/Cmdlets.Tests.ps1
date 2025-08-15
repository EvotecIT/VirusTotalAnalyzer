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
}
