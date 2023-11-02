function Remove-Win11Bloatware {
    begin {
        #Check OS
        $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
        Switch -Wildcard ( $OS ) {
            '21*' {
                $OSVer = "Windows 10"
                Write-Warning "This script is intended for use on Windows 11 devices. $($OSVer) was detected..."
                Exit 1
            }
        }

        $details = Get-CimInstance -ClassName Win32_ComputerSystem
        $manufacturer = $details.Manufacturer
        $AllInstalledApps = @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object {
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

        $StopProcess = @()
        $InstalledPackages = @()
        $ProvisionedPackages = @()
        $InstalledPrograms = @()

        if ($manufacturer -like "*HP*") {
            Write-Host "HP detected"
            $HPidentifier = "AD2F1837"
            $WhitelistedApps = @()
            $UninstallPrograms = (Get-ModuleConfig).CleanUp.Manufacturer.HP.Programs
            $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { ($UninstallPackages -contains $_.DisplayName) -or ($_.DisplayName -match "^$HPidentifier") }
            $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object { ($UninstallPackages -contains $_.Name) -or ($_.Name -match "^$HPidentifier") }
        }

        $InstalledPrograms = $AllInstalledApps | Where-Object { $UninstallPrograms -contains $_.Name }
    }
    process {
        # Stop Process
        Write-Host "Stoping Processes"
        foreach ($process in $StopProcess) {
            write-host "Stopping Process $process"
            Get-Process -Name $process | Stop-Process -Force
            write-host "Process $process Stopped"
        }

        # Remove provisioned packages first
        Write-Host "Removing Provisioned packages"
        ForEach ($ProvPackage in $ProvisionedPackages) {
            Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."
            Try {
                $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
                Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
            }
            Catch {
                Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"
            }
        }

        # Remove appx packages
        Write-Host "Removing packages"
        ForEach ($AppxPackage in $InstalledPackages) {
            Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."
            Try {
                $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
                Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
            }
            Catch {
                Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"
            }
        }

        # Remove installed programs
        Write-Host "Removing Installed Apps "
        ForEach ($InstalledProgram in $InstalledPrograms) {
            Write-Host -Object "Attempting to uninstall: [$($InstalledProgram.Name)]..."
            $uninstallcommand = $InstalledProgram.String
            Try {
                if ($uninstallcommand -match "^msiexec*") {

                    $uninstallcommand = $uninstallcommand -replace "msiexec.exe", ""
                    Start-Process 'msiexec.exe' -ArgumentList $uninstallcommand -NoNewWindow -Wait
                }
                else {
                    $string2 = $uninstallcommand
                    start-process $string2
                }
                Write-Host -Object "Successfully uninstalled: [$($InstalledProgram.Name)]"
            }
            Catch {
                Write-Warning -Message "Failed to uninstall: [$($InstalledProgram.Name)]"
            }
        }

        # Remove installed programs via CIM
        Write-Host "Removing Installed Apps via CIM"
        foreach ($program in $UninstallPrograms) {
            Write-Host -Object "Attempting to uninstall: [$($program)]..."
            Get-CimInstance -Classname Win32_Product | Where-Object Name -Match $program | Invoke-CimMethod -MethodName UnInstall
        }
    }
    end {
        Write-Host "Cleaning Done"
    }
}


    # [CmdletBinding()]
    # param ()
    # begin {
    #     $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    #     Switch -Wildcard ( $OS ) {
    #         '21*' {
    #             $OSVer = "Windows 10"
    #             Write-Warning "This script is intended for use on Windows 11 devices. $($OSVer) was detected..."
    #             Exit 1
    #         }
    #     }

    #     $details = Get-CimInstance -ClassName Win32_ComputerSystem
    #     $manufacturer = $details.Manufacturer

    #     $AppPackageList = Get-AppxProvisionedPackage -Online
    #     $AppPackageRemoveList = (Get-ModuleConfig).OS.Windows11

    #     $StopProcess = @()
    #     $UninstallPrograms = @()
    #     $UninstallProgramsWhitelist = @()
    #     $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {(($_.Name -in $UninstallPrograms))}
    #     $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {(($_.Name -in $UninstallPrograms))}

    #     v
    #

    #     $InstalledPrograms = $AllInstalledApps | Where-Object { $UninstallPrograms -contains $_.DisplayName }
    # }

    # process {
    #     $StopProcess | ForEach-Object {
    #         write-host "Stopping Process $_"
    #         Get-Process -Name $_ | Stop-Process -Force
    #         write-host "Process $_ Stopped"
    #     }

    #     $AppPackageRemoveList | ForEach-Object {
    #         $PackageName = $AppPackageList | Where-Object -Property "DisplayName" -Value $_ -EQ | Select-Object -First 1
    #         if ([string]::IsNullOrEmpty($PackageName)) {
    #             continue
    #         }

    #         Write-Host $PackageName
    #         $RemoveAppx = Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers

    #         $AppProvisioningPackageNameReCheck = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $_ } | Select-Object -ExpandProperty PackageName -First 1
    #         If ([string]::IsNullOrEmpty($AppProvisioningPackageNameReCheck) -and ($RemoveAppx.Online -eq $true)) {
    #             Write-Host @CheckIcon
    #             Write-Host " (Removed)"
    #             Write-LogEntry -Value "$($BlackListedApp) removed"
    #         }
    #     }

    #     $InstalledPrograms | ForEach-Object {
    #         Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."
    #         $uninstallcommand = $_.String
    #         Try {
    #             if ($uninstallcommand -match "^msiexec*") {
    #                 #Remove msiexec as we need to split for the uninstall
    #                 $uninstallcommand = $uninstallcommand -replace "msiexec.exe", ""
    #                 #Uninstall with string2 params
    #                 Start-Process 'msiexec.exe' -ArgumentList $uninstallcommand -NoNewWindow -Wait
    #             }
    #             else {
    #                 #Exe installer, run straight path
    #                 $string2 = $uninstallcommand
    #                 start-process $string2
    #             }
    #             #$A = Start-Process -FilePath $uninstallcommand -Wait -passthru -NoNewWindow;$a.ExitCode
    #             #$Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
    #             Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
    #         }
    #         Catch {
    #             Write-Warning -Message "Failed to uninstall: [$($_.Name)]"
    #         }


    #     }
    # }
    # end {

    # }



