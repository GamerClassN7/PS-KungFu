function Set-IPProfile {
    [CmdletBinding(DefaultParameterSetName = 'StaticNetwork')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'AutoNetwork')]
        [switch]
        $Auto,
        [Parameter(Mandatory = $false, ParameterSetName = 'StaticNetwork')]
        [string]
        $AdapterName,
        [Parameter(Mandatory = $true, ParameterSetName = 'StaticNetwork')]
        [System.Net.IPAddress]
        $NewIP,
        [Parameter(Mandatory = $true, ParameterSetName = 'StaticNetwork')]
        [System.Net.IPAddress]
        $NewSub,
        [Parameter(Mandatory = $true, ParameterSetName = 'StaticNetwork')]
        [System.Net.IPAddress]
        $NewGat,
        [Parameter(Mandatory = $true, ParameterSetName = 'StaticNetwork')]
        [System.Net.IPAddress]
        $DNS1,
        [Parameter(Mandatory = $true, ParameterSetName = 'StaticNetwork')]
        [System.Net.IPAddress]
        $DNS2
    )

    if ([string]::IsNullOrEmpty($AdapterName)) {
        $AdapterName = "Ethernet"
    }

    if (-not $Auto) {
        netsh.exe int ipv4 set dnsservers name=$AdapterName source=static address=$DNS1 register=both validate=yes
        netsh.exe int ipv4 add dnsservers name=$AdapterName address=$DNS2
        netsh.exe int ipv4 set address name=$AdapterName Source='static' address=$NewIP mask=$NewSub gateway=$NewGat gwmetric=1 store=persistent
    }
    else {
        netsh.exe int ipv4 set dnsservers name=$AdapterName source='dhcp'
        netsh.exe int ipv4 set address name=$AdapterName Source='dhcp'
    }
}