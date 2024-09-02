<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$ImportPath = $ScriptDir + '\JSON\DeviceConfiguration'

####################################################

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

Function Add-DeviceConfigurationPolicy() {

    <#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

    [CmdletBinding()]

    param
    (
        $JSON
    )

    $graphApiVersion = 'Beta'
    $DCP_resource = 'deviceManagement/deviceConfigurations'
    Write-Verbose "Resource: $DCP_resource"

    try {

        if ([string]::IsNullOrWhiteSpace($JSON)) {

            Write-Host 'No JSON specified, please specify valid JSON for the Policy...' -f Red
        }

        else {

            Test-Json -Json $JSON

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }

    }
    catch {

        $ex = $_.Exception

        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break

    }

}

####################################################

Function Add-DeviceConfigurationPolicyAssignment() {

    <#
.SYNOPSIS
This function is used to add a device configuration policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy assignment
.EXAMPLE
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
Adds a device configuration policy assignment in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicyAssignment
#>

    [CmdletBinding()]

    param
    (
        $ConfigurationPolicyId,
        $TargetGroupId,
        $Assignment
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assignments"

    try {

        if (!$ConfigurationPolicyId) {

            Write-Host 'No Configuration Policy Id specified, specify a valid Configuration Policy Id' -f Red
            break

        }

        if (!$TargetGroupId) {

            Write-Host 'No Target Group Id specified, specify a valid Target Group Id' -f Red
            break

        }
        if (!$Assignment) {

            Write-Host 'No Assignment Type specified, specify a valid Assignment Type' -f Red
            break
        }

        $ConfPolAssign = "$ConfigurationPolicyId" + '_' + "$TargetGroupId"

        $JSON = @"

        {
    "target": {
    "@odata.type": "$Assignment",
    "groupId": "$TargetGroupId"
                }
        }
"@

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
    }

    catch {

        $ex = $_.Exception


        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break

    }
}

####################################################

Function Get-DeviceConfigurationPolicy() {

    <#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy
#>

    [CmdletBinding()]

    param
    (
        $name
    )

    $graphApiVersion = 'Beta'
    $DCP_resource = 'deviceManagement/deviceConfigurations'

    try {

        if ($Name) {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method Get).Value

        }
    }

    catch {

        $ex = $_.Exception

        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break

    }

}

####################################################

Function Get-AADGroup() {

    <#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup
#>

    [CmdletBinding()]

    param
    (
        $GroupName,
        $id,
        [switch]$Members
    )

    # Defining Variables
    $graphApiVersion = 'v1.0'
    $Group_resource = 'groups'
    # pseudo-group identifiers for all users and all devices
    [string]$AllUsers = 'acacacac-9df4-4c7d-9d50-4ef0226f57a9'
    [string]$AllDevices = 'adadadad-808e-44e2-905a-0b7873a8a531'

    try {

        if ($id) {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
            switch ( $id ) {
                $AllUsers { $grp = [PSCustomObject]@{ displayName = 'All users' }; $grp }
                $AllDevices { $grp = [PSCustomObject]@{ displayName = 'All devices' }; $grp }
                default { (Invoke-MgGraphRequest -Uri $uri -Method Get).Value }
            }

        }

        elseif ([string]::IsNullOrWhiteSpace($GroupName)) {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method Get).Value

        }

        else {

            if (!$Members) {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get).Value

            }

            elseif ($Members) {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                $Group = (Invoke-MgGraphRequest -Uri $uri -Method Get).Value

                if ($Group) {

                    $GID = $Group.id

                    $Group.displayName
                    Write-Host

                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                (Invoke-MgGraphRequest -Uri $uri -Method Get).Value

                }
            }
        }
    }

    catch {

        $ex = $_.Exception

        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    }

}

####################################################

Function Test-JSON() {

    <#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

    param (
        $JSON
    )

    try {

        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $validJson = $true
    }

    catch {

        $validJson = $false
        $_.Exception

    }

    if (!$validJson) {

        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    }
}

####################################################

#region Authentication

Write-Host

if ([string]::IsNullOrWhiteSpace($User)) {

    $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
    Write-Host
}

Test-MgAuth -User $User

#endregion

####################################################

# Setting application AAD Group to assign Policy

#$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"

#$TargetGroupId = (Get-AADGroup | Where-Object {$_.displayName -eq $AADGroup}).id
#
#    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){
#
#    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
#    Write-Host
#    exit

#    }

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"', '')

if (!(Test-Path "$ImportPath")) {

    Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

####################################################

Get-ChildItem $ImportPath -Filter *.json |
ForEach-Object {

    $JSON_Data = Get-Content $_.FullName

    # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
    $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags

    $DisplayName = $JSON_Convert.displayName

    $DuplicateDCP = Get-DeviceConfigurationPolicy -Name $JSON_Convert.displayName

    If ($DuplicateDCP -eq $null) {
        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5

        Write-Host
        Write-Host "Device Configuration Policy '$DisplayName' Found..." -ForegroundColor Yellow
        Write-Host
        $JSON_Output
        Write-Host
        Write-Host "Adding Device Configuration Policy '$DisplayName'" -ForegroundColor Yellow

        Add-DeviceConfigurationPolicy -JSON $JSON_Output

        $DeviceConfigs = Get-DeviceConfigurationPolicy -name $DisplayName

        $DeviceConfigID = $DeviceConfigs.id

        Write-Host "Device ConfigID '$DeviceConfigID'" -ForegroundColor Yellow
        Write-Host
        $AADGroups = $JSON_Convert.assignments.target

        foreach ($AADGroup in $AADGroups ) {
            Write-Host 'AAD Group Name:' $AADGroup.groupId -ForegroundColor Yellow
            Write-Host 'Assignment Type:' $AADGroup.'@OData.type' -ForegroundColor Yellow

            $TargetGroupId = (Get-AADGroup -GroupName $AADGroup.groupid)
            Write-Host 'Included Group ID:' $TargetGroupID.Id -ForegroundColor Yellow
            Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DeviceConfigID -TargetGroupId $TargetGroupId.id -Assignment $AADGroup.'@OData.type'
        }

        # Create exclude Group

        <#$ShortName =  $JSON_Convert.displayName -replace "PAW-Global-2009-Intune-Configuration-", ''
    $ExcludeGroup = "PAW-"+$ShortName+"-Exclude-Device"
        If (Get-AzureADGroup -SearchString $ExcludeGroup) {
            Write-Host
            Write-Host "AAD group" $ExcludeGroup "already exists!" -f Yellow
            Write-Host
        }
        Else {

            $MailNickName = $ShortName+"-G"

            try
            {
                $ExcludeTargetGroup = New-AzureADGroup -DisplayName $ExcludeGroup -Description $ExcludeGroup"-Group" -MailEnabled $false -SecurityEnabled $true -MailNickName $MailNickName
                sleep 5
            }
            catch
            {
              Write-Host
              Write-Host "Error creating AAD group" $ExcludeGroup -f Red
              Write-Host
            }

            }

    Write-Host "Excluded Group ID" $ExcludeTargetGroup.objectid
    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DeviceConfigID -TargetGroupId $ExcludeTargetGroup.objectid -Assignment "exclusionGroupAssignmentTarget"
 #>
    }

    else {
        Write-Host 'Device Configuration Profile:' $JSON_Convert.displayName 'has already been created' -ForegroundColor Yellow
    }

}
