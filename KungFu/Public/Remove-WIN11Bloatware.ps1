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
        $AllInstalledApps = Get-UninstallStrings

        $StopProcess = @()
        $InstalledPackages = @()
        $ProvisionedPackages = @()
        $InstalledPrograms = @()
        $WhitelistedApps = @()

        if ($manufacturer -like "*HP*") {
            Write-Host "HP detected"
            $HPidentifier = "AD2F1837"
            $WhitelistedApps = @(
                "AD2F1837.HPSupportAssistant"
            )
            $UninstallPrograms = (Get-ModuleConfig).CleanUp.Manufacturer.HP.Programs
            $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { ($UninstallPackages -contains $_.DisplayName) -or ($_.DisplayName -match "^$HPidentifier") -and ($_.Name -NotMatch $WhitelistedApps)}
            $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object { ($UninstallPackages -contains $_.Name) -or ($_.Name -match "^$HPidentifier") -and ($_.Name -NotMatch $WhitelistedApps) }
        }

        if ($manufacturer -like "*Dell*") {
            Write-Host "Dell detected"
            $WhitelistedApps = @(
                "WavesAudio.MaxxAudioProforDell2019"
                "Dell - Extension*"
                "Dell, Inc. - Firmware*"
            )
            $UninstallPrograms = (Get-ModuleConfig).CleanUp.Manufacturer.Dell.Programs
            $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { (($_.Name -in $UninstallPrograms) -or ($_.Name -like "*Dell*")) -and ($_.Name -NotMatch $WhitelistedApps) }
            $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object { (($_.Name -in $UninstallPrograms) -or ($_.Name -like "*Dell*")) -and ($_.Name -NotMatch $WhitelistedApps) }

        }

        if ($manufacturer -like "*Lenovo*") {
            Write-Host "Lenovo detected"
            $StopProcess = (Get-ModuleConfig).CleanUp.Manufacturer.Lenovo.Process

            $UninstallPrograms = (Get-ModuleConfig).CleanUp.Manufacturer.HP.Programs
            $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { ($UninstallPackages -contains $_.DisplayName) -or ($_.DisplayName -match "^$HPidentifier") }
            $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object { ($UninstallPackages -contains $_.Name) -or ($_.Name -match "^$HPidentifier") }
        }

        $InstalledPrograms = $AllInstalledApps | Where-Object { $UninstallPrograms -contains $_.Name -and ($_.Name -NotMatch $WhitelistedApps) }
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
        #TODO: Move to Conf File
        # Bing Downloaded Maps Manager
        Get-Service "MapsBroker" | Stop-Service | Out-Null
        Get-Service "MapsBroker" | Set-Service -StartupType Disabled | Out-Null
        Write-Host "Bing Downloaded Maps Manager [DISABLED]" -ForegroundColor Green

        # Parental Controls
        Get-Service "WpcMonSvc" | Stop-Service | Out-Null
        Get-Service "WpcMonSvc" | Set-Service -StartupType Disabled | Out-Null
        Write-Host "Parental Controls [DISABLED]" -ForegroundColor Green

        # Parental Controls
        Get-Service "WpcMonSvc" | Stop-Service | Out-Null
        Get-Service "WpcMonSvc" | Set-Service -StartupType Disabled | Out-Null
        Write-Host "Parental Controls [DISABLED]" -ForegroundColor Green
        # Windows Mobile Hotspot Service
        Get-Service "icssvc" | Stop-Service | Out-Null
        Get-Service "icssvc" | Set-Service -StartupType Disabled | Out-Null
        Write-Host "Windows Mobile Hotspot Service [DISABLED]" -ForegroundColor Green
        # Windows Media Player Network Share
        Get-Service "WMPNetworkSvc" | Stop-Service | Out-Null
        Get-Service "WMPNetworkSvc" | Set-Service -StartupType Disabled | Out-Null
        Write-Host "Windows Media Player Network Share [DISABLED]" -ForegroundColor Green
        # Windows Mixed Reality OpenXR Service
        Get-Service "MixedRealityOpenXRSvc" | Stop-Service | Out-Null
        Get-Service "MixedRealityOpenXRSvc" | Set-Service -StartupType Disabled | Out-Null
        Write-Host "Windows Mixed Reality OpenXR Service [DISABLED]" -ForegroundColor Green
        Write-Host "Cleaning Done"
    }
}

