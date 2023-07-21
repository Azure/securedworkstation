<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

# Determine script location for PowerShell
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

Function Set-AADAuth {
    <#
    .SYNOPSIS
    This function is used to authenticate with the Azure AD interface
    .DESCRIPTION
    The function authenticate with the Azure AD Interface with the tenant name
    .EXAMPLE
    Set-AADAuth
    Authenticates you with the Azure AD interface
    .NOTES
    NAME: Set-AADAuth
    #>
    
    [cmdletbinding()]
    
    param
    (
        #[Parameter(Mandatory=$true)]
        $User
    )
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

    Write-Host "Checking for Microsoft Graph module..."
    
        $MgModule = Get-Module -Name "Microsoft.Graph" -ListAvailable
    
        if ($null -eq $MgModule) {
            write-host
            write-host "Microsoft Graph Powershell module not installed..." -f Red
            write-host "Attempting module install now" -f Red
            Install-Module -Name Microsoft.Graph -AllowClobber -Force
            write-host
        }

        $tenant = $userUpn.Host
        
        Connect-MgGraph -TenantId $tenant
    }
    
####################################################
    
    $User = Read-Host -Prompt "Please specify your user principal name for Microsoft Authentication"
    

    Set-AADAuth -user $user
    
 ####################################################
    
    
 #write-host "Adding App Registrtion"

 #. $ScriptDir/AppRegistration_Create.ps1
 
 #Start-Sleep -s 5

#write-host "Adding required AAD Groups"

# . $ScriptDir/AADGroups_Create.ps1

#write-host "Adding AAD Group Membership"

# . $ScriptDir/AADGroupMemberships_Add.ps1

# Start-Sleep -s 5

#write-host "Adding Named Locations"

#. $ScriptDir/NamedLocations_Import.ps1 -user $user

#Start-Sleep -s 5

#write-host "Adding Conditional Access Policies"

#. $ScriptDir/CA-Policies-Import_PAW.ps1 -State "Disabled"

#Start-Sleep -s 5

write-host "Adding Device Configuration Profiles"

. $ScriptDir/Import-PAW-DeviceConfiguration.ps1

#Start-Sleep -s 5

write-host "Adding Device Compliance Policies"

. $ScriptDir/Import-PAW-DeviceCompliancePolicies.ps1

Start-Sleep -s 5

write-host "Adding Update Rings Policy"

. $ScriptDir/Import-PAW-DeviceConfigurationADMX.ps1

Start-Sleep -s 5

#write-host "Adding Enrollment Status Page"

#. $ScriptDir/ESP_Import.ps1

#Start-Sleep -s 5

#write-host "Adding AutoPilot Profile"

#. $ScriptDir/AutoPilot_Import.ps1

#Start-Sleep -s 5

#write-host "Adding Device Enrollment Restrictions"

#. $ScriptDir/DER-Import_PAW.ps1

#Start-Sleep -s 5



