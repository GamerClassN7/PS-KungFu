function Test-MicrosoftOfficeEndpoint {   
    $ProgressPreference = "SilentlyContinue"
    try {
        $site = Invoke-WebRequest -Uri 'https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide' -UseBasicParsing
        $json_file_link = ($site.Links | where-Object OuterHTML -match 'JSON formatted').href
    }
    catch {
        return 
    }

    try {
        $Endpoints = Invoke-WebRequest -Uri $json_file_link -ErrorAction Stop | ConvertFrom-Json
    }
    catch {
        return
    }

    $results = @()
    $Test_Endpoints = $Endpoints | Where-Object urls -ne $null | Select-Object urls, tcpports, udpports, ips, notes
    foreach ($item in $Test_Endpoints) {
        foreach ($port in $($item.tcpPorts -split ",")) {
            foreach ($url in $item.urls ) {
                if ($url.Contains("*")) {
                    $Status = "Failed or couldn't resolve DNS name"
                    Write-Warning ("Skipping {0} because it's a wildcard address" -f $testurl)
                } else {                    
                    $Status = Test-Connection -TcpPort $port -ComputerName $url  -ErrorAction SilentlyContinue
                    if ($Status  -eq $true){
                        Write-Host ("{0} is reachable on TCP port {1} ({2}) using IP-Address {3}" -f $url, $port, $item.notes, $($item.ips -join (', '))) -ForegroundColor Green
                    }
                }

                $results +=  [PSCustomObject]@{
                    Status          = $Status
                    URL             = $url
                    TCPport         = $port
                    Notes           = $item.notes
                    EndpointIPrange = $item.ips
                }
            }
        }
    }

    $results | Sort-Object URL, TCPport | Format-Table
}