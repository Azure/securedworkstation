<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>


$script:ScriptName = $myInvocation.MyCommand.Name
$script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
$script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
$script:logFile = "$env:Temp\$LogName.log"

Function Start-Log {
        param (
            [string]$FilePath,

            [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
            [switch]$DeleteExistingFile
        )
		
        Try {
            If (!(Test-Path $FilePath)) {
                ## Create the log file
                New-Item $FilePath -Type File -Force | Out-Null
            }
            
            If ($DeleteExistingFile) {
                Remove-Item $FilePath -Force
            }
			
            ## Set the global variable to be used as the FilePath for all subsequent Write-Log
            ## calls in this session
            $script:ScriptLogFilePath = $FilePath
        }
        Catch {
            Write-Error $_.Exception.Message
        }
    }

    ####################################################

    Function Write-Log {
        #Write-Log -Message 'warning' -LogLevel 2
        #Write-Log -Message 'Error' -LogLevel 3
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,
			
            [Parameter()]
            [ValidateSet(1, 2, 3)]
            [int]$LogLevel = 1,

            [Parameter(HelpMessage = 'Outputs message to Event Log,when used with -WriteEventLog')]
            [switch]$WriteEventLog
        )
        Write-Host
        Write-Host $Message
        Write-Host
        $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
        $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
        $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
        $Line = $Line -f $LineFormat
        Add-Content -Value $Line -Path $ScriptLogFilePath
        If ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
    }

Function Is-VM {
        <#
.SYNOPSIS
This function checks WMI to determine if the device is a VM
.DESCRIPTION
This function checks WMI to determine if the device is a VM
.EXAMPLE
Is-VM
This function checks WMI to determine if the device is a VM
.NOTES
NAME: Is-VM
#>

        [CmdletBinding()]
        Param ()
    
        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            Write-Log -Message "Checking WMI class: Win32_ComputerSystem for string: *virtual*"
            Try {
                $ComputerSystemInfo = Get-CIMInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                #$ComputerSystemInfo
                if ($ComputerSystemInfo.Model -like "*virtual*") {
                    Write-Log -Message "Virtual string detected"
                    $True
                }
                else {
                    Write-Log -Message "Virtual string not found"          
                    $False
                }
            }
            Catch [Exception] {
                Write-Log -Message "Error occurred: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            }
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
    }

    Start-Log -FilePath $logFile -DeleteExistingFile
    Write-Host
    Write-Host "Script log file path is [$logFile]" -ForegroundColor Cyan
    Write-Host


#region IsVM
        If (Is-VM) {
            Write-Log -Message "Machine is a VM"
        }
        Else {
            Write-Host "Machine is a physical device"
       
            #Enable Hibernate
            Write-Log -Message "Enabling Hibernation"
            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/HIBERNATE"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable hibernate: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            Try {
                New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Explorer -Name ShowHibernateOption -Value 1 -PropertyType DWORD -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to apply ShowHibernate regkey: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/Change hibernate-timeout-ac 300"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable hibernate ac timeout: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/Change hibernate-timeout-dc 30"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable hibernate dc timeout: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }
        
            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/Change standby-timeout-ac 60"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable standby ac timeout: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            Write-Log -Message 'Show Hibernate option in Shutdown Menu'
            $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
            $regProperties = @{
                Name         = 'ShowHibernateOption'
                Value        = '1'
                PropertyType = 'DWORD'
                ErrorAction  = 'Stop'
            }

            Try {
                $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            }
            Catch [System.Management.Automation.ItemNotFoundException] {
                Write-Log -Message "Error: $registryPath path not found, attempting to create..."
                $Null = New-Item -Path $registryPath -Force
                $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            }
            Catch {
                Write-Log -Message "Error changing registry: $($_.Exception.message)"
                Write-Warning "Error: $($_.Exception.message)"        
                Exit
            }
            Finally {
                Write-Log -Message "Finished changing registry"
            }
        }
        #endregion IsVM

        #region Configure AppLocker DLL rule registry key
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp\DLL\2"
        Write-Log -Message "Create registry path: $registryPath"
        Try {
            $Null = New-Item -Path $registryPath -Force
        }
        Catch {
            Write-Log -Message "Error changing AppLocker DLL rule registry key: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"        
            Exit
        }
        Finally {
           Write-Log -Message "Finished changing AppLocker DLL rule registry key"
        }
        #endregion Configure AppLocker DLL rule registry key
        
        #region Configure additional Defender for Endpoint security recommendations that cannot be set in Configuration Profiles
        #Handle registry changes
        
        
        Write-Log -Message "Configuring additional Defender for Endpoint security recommendations that cannot be set in Configuration Profiles"
        # Require users to elevate when setting a network's location - prevent changing from Public to Private firewall profile
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_StdDomainUserSetLocation -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Require users to elevate when setting a network's location - prevent changing from Public to Private firewall profile registry update successfully applied"
        # Prevent saving of network credentials 
        New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name DisableDomainCreds -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Prevent saving of network credentials registry update successfully applied"
        # Prevent changing proxy config
                
        #region Disable Network Location Wizard - prevents users from setting network location as Private and therefore increasing the attack surface exposed in Windows Firewall
        #region Disable Network Location Wizard
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"
        $regProperties = @{
            Name        = "NewNetworkWindowOff"
            ErrorAction = "Stop"
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"        
            Exit
        }
        Finally {
            Write-Host "Finished Disable Network Location Wizard in registry"
        }
        #endregion Disable Network Location Wizard


		#region Remove Powershell 2.0
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
            Write-Log -Message "Removed Powershell v2.0"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove Powershell v2.0: $($_.Exception.message)"
        }
        #endregion Remove Powershell 2.0

        #region Remove WorkFolders-Client
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -ErrorAction Stop
            Write-Log -Message "Removed WorkFolders"
        }
        catch {
            Write-Log -Message "Failed to remove WorkFolders"
            Write-Log -Message "Error occurred trying to remove Powershell v2.0: $($_.Exception.message)"
        }
        #endregion Remove WorkFolders-Client

        #region Remove XPS Printing
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features -ErrorAction Stop
            Write-Log -Message "Removed XPS Printing"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove XPS Printing: $($_.Exception.message)"
        }
        #endregion Remove XPS Printing

        #region Remove WindowsMediaPlayer
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -ErrorAction Stop
            Write-Log -Message "Removed Windows Media Player"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove Windows Media Player: $($_.Exception.message)"
        }
        #endregion Remove WindowsMediaPlayer

    
		#region RegistryChanges - Set W32Time Parameter Type to NTP
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
        $regProperties = @{
            Name         = "Type"
            Value        = "NTP"
            PropertyType = "String"
            ErrorAction  = "Stop"
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Updated Set W32Time Parameter Type to NTP in registry"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"        
            Exit
        }
        Finally {
            Write-Log -Message "Finished Set W32Time Parameter Type to NTP"
        }
        #endregion RegistryChanges - Set W32Time Parameter Type to NTP

        #region RegistryChanges - Set Auto Time Sync Service to Automatic start
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate"
        $regProperties = @{
            Name         = "Start"
            Value        = "3"
            PropertyType = "DWORD"
            ErrorAction  = "Stop"
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Set Auto Time Sync Service to Automatic start in registry"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"        
            Exit
        }
        Finally {
            Write-Log -Message "Set Auto Time Sync Service to Automatic start"
        }
        #endregion RegistryChanges - Set Auto Time Sync Service to Automatic start
       

        #region Remove Internet Explorer 11
        <#try {
            Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart #-ErrorAction Stop
            Write-Log -Message "Removed Internet Explorer 11"
            }
        catch {
            Write-Log -Message "Error occurred trying to remove Internet Explorer 11: $($_.Exception.message)"
              }

              Finally {
            Write-Log -Message "Finished removing Internet Explorer"
        }#>
        #endregion Remove Internet Explorer 11