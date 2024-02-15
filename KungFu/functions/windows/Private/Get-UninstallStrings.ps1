function Get-UninstallStrings {
    return @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object {
        if (-not (Test-Path -Path $_)) {
            return
        }

        return Get-ChildItem -Path $_ | Get-ItemProperty | Select-Object -Property DisplayName, UninstallString | ForEach-Object {
            $string1 = $_.uninstallstring
            #Check if it's an MSI install
            if ($string1 -match "^msiexec*") {
                #MSI install, replace the I with an X and make it quiet
                $string2 = $string1 + " /quiet /norestart"
                $string2 = $string2 -replace "/I", "/X "
                #Uninstall with string2 params
                return New-Object -TypeName PSObject -Property @{
                    Name   = $_.DisplayName
                    String = $string2
                }
            }
            else {
                #Exe installer, run straight path
                $string2 = $string1
                return New-Object -TypeName PSObject -Property @{
                    Name   = $_.DisplayName
                    String = $string2
                }
            }
        }
    }
}