function ConvertTo-VTBody {
    <#
    .SYNOPSIS
    Converts file to memory stream to create body for Invoke-RestMethod and send it to Virus Total.

    .DESCRIPTION
    Converts file to memory stream to create body for Invoke-RestMethod and send it to Virus Total.

    .PARAMETER FileInformation
    Path to a file to send to Virus Total

    .PARAMETER Boundary
    Boundary information to say where the file starts and ends.

    .EXAMPLE
    $Boundary = [Guid]::NewGuid().ToString().Replace('-', '')
    ConvertTo-VTBody -File $File -Boundary $Boundary

    .NOTES
    Notes

    #>
    [cmdletBinding()]
    param(
        [parameter(Mandatory)][System.IO.FileInfo] $FileInformation,
        [string] $Boundary
    )
    [byte[]] $CRLF = 13, 10 # ASCII code for CRLF

    $MemoryStream = [System.IO.MemoryStream]::new()

    $BoundaryInformation = [System.Text.Encoding]::ASCII.GetBytes("--$Boundary")
    $MemoryStream.Write($BoundaryInformation, 0, $BoundaryInformation.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    $FileData = [System.Text.Encoding]::ASCII.GetBytes("Content-Disposition: form-data; name=`"file`"; filename=$($FileInformation.Name);")
    $MemoryStream.Write($FileData, 0, $FileData.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    $ContentType = [System.Text.Encoding]::ASCII.GetBytes('Content-Type:application/octet-stream')
    $MemoryStream.Write($ContentType, 0, $ContentType.Length)

    $MemoryStream.Write($CRLF, 0, $CRLF.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    $FileContent = [System.IO.File]::ReadAllBytes($FileInformation.FullName)
    $MemoryStream.Write($FileContent, 0, $FileContent.Length)

    $MemoryStream.Write($CRLF, 0, $CRLF.Length)
    $MemoryStream.Write($BoundaryInformation, 0, $BoundaryInformation.Length)

    $Closure = [System.Text.Encoding]::ASCII.GetBytes('--')
    $MemoryStream.Write($Closure, 0, $Closure.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    , $MemoryStream.ToArray()
}