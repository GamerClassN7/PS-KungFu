[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Get-ChildItem (Split-Path $script:MyInvocation.MyCommand.Path) -Filter '*.ps1' -Recurse | ForEach-Object {
    if (($IsLinux -and $_.FullName -like "*/linux/*") -or $_.FullName -like "*/common/*" ){
        . $_.FullName
    } elseif (($IsWindows -and $_.FullName -like "*/windows/*") -or $_.FullName -like "*/common/*" ){
        . $_.FullName
    } elseif (($IsMacOS -and $_.FullName -like "*/mac/*") -or $_.FullName -like "*/common/*" ){
        . $_.FullName
    }
}

# Validate and try to import available modules
# (Import-PowerShellDataFile -Path $($script:MyInvocation.MyCommand.Path -replace "psm1", "psd1")).RequiredModules | ForEach-Object {
#     Test-Module -Name $_
# }

Get-ChildItem (Split-Path $script:MyInvocation.MyCommand.Path) -Filter '*.ps1'  -Recurse | ForEach-Object {
    if (($IsLinux -and $_.FullName -like "*/linux/public/*") -or $_.FullName -like "*/common/public/*" ){
        Export-ModuleMember -Function $_.BaseName
    } elseif (($IsWindows -and $_.FullName -like "*/windows/public/*") -or $_.FullName -like "*/common/public/*" ){
        Export-ModuleMember -Function $_.BaseName
    } elseif (($IsMacOS -and $_.FullName -like "*/mac/public/*") -or $_.FullName -like "*/common/public/*" ){
        Export-ModuleMember -Function $_.BaseName
    }
}

