function Optimize-Teams {
    $TeamConfig = Get-Content -Path ("{0}\Microsoft\Teams\desktop-config.json" -f $env:APPDATA) -Raw |ConvertFrom-Json
    $TeamConfig | Add-Member -Type NoteProperty -Value $true -Name "disableGpu"
    $TeamConfig | COnvertto-json | Set-Content -Path ("{0}\Microsoft\Teams\desktop-config.json" -f $env:APPDATA) -Force
}