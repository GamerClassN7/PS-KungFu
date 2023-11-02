function Get-PublicIP {
    $Providers = @("icanhazip.com","ifconfig.me", "api.ipify.org", "ipinfo.io/ip", "ipecho.net/plain")
    $SelectedProvider = $($Providers[$(Get-Random -Maximum $Providers.Length)])
    write-host $SelectedProvider
    return (Invoke-RestMethod -Uri $SelectedProvider).Trim()
}

