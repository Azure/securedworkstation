<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

# Determine script location for PowerShell
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

function Test-MgAuth {

    <#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Test-MgAuth
Authenticates you with the Graph API interface
.NOTES
NAME: Test-MgAuth
#>

    [CmdletBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    $userUpn = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host 'Checking for Microsoft Graph module...'

    $MgModule = Get-Module -Name 'Microsoft.Graph' -ListAvailable

    if ($null -eq $MgModule) {
        Write-Host
        Write-Host 'Microsoft Graph Powershell module not installed...' -f Red
        Write-Host "Install by running 'Install-Module Microsoft.Graph' or 'Install-Module Microsoft.Graph' from an elevated PowerShell prompt" -f Yellow
        Write-Host "Script can't continue..." -f Red
        Write-Host
    }

    $scopes = @()

    #########################################
    # Directory related scopes              #
    #########################################
    $scopes += @('Device.Read.All',
        'User.Read.All',
        'GroupMember.ReadWrite.All',
        'Group.ReadWrite.All',
        'Directory.ReadWrite.All')

    #########################################
    # Device Management scopes              #
    #########################################
    $scopes += @('DeviceManagementConfiguration.ReadWrite.All',
        'DeviceManagementServiceConfig.ReadWrite.All',
        'DeviceManagementRBAC.ReadWrite.All',
        'DeviceManagementManagedDevices.ReadWrite.All',
        'DeviceManagementApps.ReadWrite.All')

    #$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    #$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    try {

        Connect-MgGraph -Scopes $scopes -TenantId $tenant

        #validate connected to proper tenant and account

        $ctx = Get-MgContext
        $org = Get-MgOrganization

        $domains = $org.VerifiedDomains | Select-Object -ExpandProperty Name
        if ($ctx.Account.ToLower() -ne $userUpn.Address.ToLower() -or ($ctx.TenantId -ne $org.Id) -or $domains -notcontains $tenant) {
            Write-Host 'Unable to verify tenant or account' -f Red
            Disconnect-MgGraph
            throw 'Unable to continue due to validation'
        }

        # $authHeader = @{
        #     'Content-Type'  = 'application/json'
        #     'Authorization' = "Bearer " + $authResult.AccessToken
        #     'ExpiresOn'     = $authResult.ExpiresOn
        # }

        # return $authHeader
    }
    catch {
        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        break

    }
}

####################################################

$User = Read-Host -Prompt 'Please specify your user principal name for Microsoft Authentication'

Test-MgAuth -user $user

####################################################

Write-Host 'Adding Device Configuration Profiles'

. $ScriptDir/Import-SPE-DeviceConfiguration.ps1

Start-Sleep -s 5

Write-Host 'Adding Device Compliance Policies'

. $ScriptDir/Import-SPE-DeviceCompliancePolicies.ps1

Start-Sleep -s 5

Write-Host 'Adding Edge Browser Policy'

. $ScriptDir/Import-SPE-DeviceConfigurationADMX.ps1

Start-Sleep -Seconds 5

#Write-host "Importing Device Config PowerShell script"

#. $ScriptDir/Import-SPE-DeviceConfigScript.ps1
