[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Get-ChildItem (Split-Path $script:MyInvocation.MyCommand.Path) -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
    #write-host $_.BaseName
}

# Validate and try to import available modules
# (Import-PowerShellDataFile -Path $($script:MyInvocation.MyCommand.Path -replace "psm1", "psd1")).RequiredModules | ForEach-Object {
#     Test-Module -Name $_
# }

#Get-ChildItem "$(Split-Path $script:MyInvocation.MyCommand.Path)\Public\*" -Filter '*.ps1' -Recurse | ForEach-Object {
#   Export-ModuleMember -Function $_.BaseName
#}
