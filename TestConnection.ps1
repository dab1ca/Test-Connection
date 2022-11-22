function TestConnectivityToEndpoint
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Endpoint
    )
    try
    {
        Write-Host "Starting connectivity test for endpoint $Endpoint.."

            
        try 
		{
            Write-Host "Testing secure connection to: $Endpoint" -ForegroundColor DarkGreen -BackgroundColor White           
                    
            $hostObject = New-Object psobject -Property @{
                Host = $Endpoint
                Port = 443
                SSLv2 = $false
                SSLv3 = $false
                TLSv1_0 = $false
                TLSv1_1 = $false
                TLSv1_2 = $false
                KeyExhange = $null
                HashAlgorithm = $null
                RemoteCertificate = $null
            }

            Test-TLSConnection -HostObject ([ref]$hostObject)
                    
            if($null -eq $hostObject.KeyExhange)
            {
                Write-Host "Unable to negotiate a secure connection. Result details: $hostObject"
                return $false
            }
            else
            {
                Write-Host "Connection negotiated successfully!" -ForegroundColor DarkGreen -BackgroundColor White               

                $global:TLSv1_0 = $hostObject.TLSv1_0
                $global:TLSv1_1 = $hostObject.TLSv1_1
                $global:TLSv1_2 = $hostObject.TLSv1_2

                if($hostObject.TLSv1_2 -eq $false)
                {                    
                    Write-Host "TLS 1.2 is not supported. Please enable TLS 1.2." -ForegroundColor Yellow -BackgroundColor Red                   
                }

                Write-Host "Connection details: $hostObject"
            }                
        }
        catch
        {
            Write-Host "Caught exception while testing connection to endpoint: $($_.Exception.Message)" -ForegroundColor Yellow -BackgroundColor Red
            return 
        }
    }
    catch
    {
        Write-Host "Caught exception while testing connection to endpoint: $($_.Exception.Message)" -ForegroundColor Yellow -BackgroundColor Red
        return 
    }
    return 
}

function Test-TLSConnection
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ref]$HostObject
    )

    "ssl2", "ssl3", "tls", "tls11", "tls12" | ForEach-Object {
        $TcpClient = New-Object Net.Sockets.TcpClient
        $TcpClient.Connect($HostObject.Value.Host, $HostObject.Value.Port)
        $SslStream = New-Object Net.Security.SslStream $TcpClient.GetStream(),
            $true,
            ([System.Net.Security.RemoteCertificateValidationCallback]{ $true })
        $SslStream.ReadTimeout = 15000
        $SslStream.WriteTimeout = 15000
        try 
        {
            $SslStream.AuthenticateAsClient($HostObject.Value.Host,$null,$_,$false)
            $HostObject.Value.RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
            $HostObject.Value.KeyExhange = $SslStream.KeyExchangeAlgorithm
            $HostObject.Value.HashAlgorithm = $SslStream.HashAlgorithm
            $status = $true
        } 
        catch 
        {
            $status = $false
        }

        switch ($_) 
        {
            "ssl2" {$HostObject.Value.SSLv2 = $status}
            "ssl3" {$HostObject.Value.SSLv3 = $status}
            "tls" {$HostObject.Value.TLSv1_0 = $status}
            "tls11" {$HostObject.Value.TLSv1_1 = $status}
            "tls12" {$HostObject.Value.TLSv1_2 = $status}
        }
        # dispose objects to prevent memory leaks
        $TcpClient.Dispose()
        $SslStream.Dispose()
    }
}

$Input = "Y"

While($Input -eq "Y") {
$InputEndpoint = Read-Host "Enter Endpoint"
TestConnectivityToEndpoint -Endpoint $InputEndpoint
$Input = Read-Host "Continue? Y/N"
}
