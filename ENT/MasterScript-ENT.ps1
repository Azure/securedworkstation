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
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Attempting module install now" -f Red
            Install-Module -Name AzureADPreview -AllowClobber -Force
            #write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            #write-host "Script can't continue..." -f Red
            write-host
            #exit
        }
    
        Connect-AzureAD -AccountId $user | Out-Null
    
    }
    
####################################################
    
    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"

    Set-AADAuth -user $user
    
 ####################################################
    
    
write-host "Adding Device Configuration Profiles"

. $ScriptDir/Import-ENT-DeviceConfiguration.ps1

Start-Sleep -s 5

write-host "Adding Device Compliance Policies"

. $ScriptDir/Import-ENT-DeviceCompliancePolicies.ps1

Start-Sleep -s 5

write-host "Adding Edge Browser Policy"

. $ScriptDir/Import-ENT-DeviceConfigurationADMX.ps1

Start-Sleep -s 5

#Write-host "Importing Device Config PowerShell script"

#. $ScriptDir/Import-SPE-DeviceConfigScript.ps1