<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$ImportPath = $ScriptDir + "\JSON\DeviceCompliance"


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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host "Checking for Microsoft Graph module..."

    $MgModule = Get-Module -Name "Microsoft.Graph" -ListAvailable

    if ($null -eq $MgModule) {
        write-host
        write-host "Microsoft Graph Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module Microsoft.Graph' or 'Install-Module Microsoft.Graph' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        
    }

    $scopes = @()

    #########################################
    # Directory related scopes              #
    #########################################
    $scopes += @("Device.Read.All", 
        "User.Read.All", 
        "GroupMember.ReadWrite.All", 
        "Group.ReadWrite.All", 
        "Directory.ReadWrite.All")

    #########################################
    # Device Management scopes              #
    #########################################
    $scopes += @("DeviceManagementConfiguration.ReadWrite.All", 
        "DeviceManagementServiceConfig.ReadWrite.All", 
        "DeviceManagementRBAC.ReadWrite.All", 
        "DeviceManagementManagedDevices.ReadWrite.All", 
        "DeviceManagementApps.ReadWrite.All")


    #$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    #$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    try {

        Connect-MgGraph -Scopes $scopes -TenantId $tenant

        #validate connected to proper tenant and account

        $ctx = Get-MgContext
        $org = Get-MgOrganization

        $domains = $org.VerifiedDomains | select-object -ExpandProperty Name
        if ($ctx.Account.ToLower() -ne $userUpn.Address.ToLower() -or ($ctx.TenantId -ne $org.Id) -or $domains -notcontains $tenant) {
            write-host "Unable to verify tenant or account" -f Red
            Disconnect-MgGraph
            throw "Unable to continue due to validation"
        }

        # $authHeader = @{
        #     'Content-Type'  = 'application/json'
        #     'Authorization' = "Bearer " + $authResult.AccessToken
        #     'ExpiresOn'     = $authResult.ExpiresOn
        # }

        # return $authHeader
    }
    catch {
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break

    }

}

####################################################

Function Add-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to add a device compliance policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device compliance policy
    .EXAMPLE
    Add-DeviceCompliancePolicy -JSON $JSON
    Adds an iOS device compliance policy in Intune
    .NOTES
    NAME: Add-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
    try {
    
        if ($JSON -eq "" -or $null -eq $JSON) {
    
            write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
    
        }
    
        else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
        }
    }
    catch {
        $ex = $_.Exception
        

        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
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

    [cmdletbinding()]

    param
    (
        $GroupName,
        $id,
        [switch]$Members
    )

    # Defining Variables
    $graphApiVersion = "v1.0"
    $Group_resource = "groups"
    # pseudo-group identifiers for all users and all devices
    [string]$AllUsers = "acacacac-9df4-4c7d-9d50-4ef0226f57a9"
    [string]$AllDevices = "adadadad-808e-44e2-905a-0b7873a8a531"

    try {

        if ($id) {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
            switch ( $id ) {
                $AllUsers { $grp = [PSCustomObject]@{ displayName = "All users" }; $grp }
                $AllDevices { $grp = [PSCustomObject]@{ displayName = "All devices" }; $grp }
                default { (Invoke-MgGraphRequest -Uri $uri -Method Get).Value }
            }
                
        }

        elseif ($GroupName -eq "" -or $null -eq $GroupName) {

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
                    write-host

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
        write-host
        break

    }

}

####################################################
Function Get-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to get device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicy
    Returns any device compliance policies configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -Name
    Returns any device compliance policies with specific display name

    .NOTES
    NAME: Get-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $Name
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get).Value | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") -and ($_.'displayName').contains($Name) }
    
    }
        
    catch {
    
        $ex = $_.Exception
        

        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
    


####################################################

Function Add-DeviceCompliancePolicyAssignment() {

    <#
    .SYNOPSIS
    This function is used to add a device compliance policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device compliance policy assignment
    .EXAMPLE
    Add-DeviceCompliancePolicyAssignment -ComplianceAssignments $ComplianceAssignments -CompliancePolicyId $CompliancePolicyId
    Adds a device compliance policy assignment in Intune
    .NOTES
    NAME: Add-DeviceCompliancePolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        $CompliancePolicyId,
        $ComplianceAssignments
    )
    
    $graphApiVersion = "v1.0"
    $Resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"
        
    try {
    
        if (!$CompliancePolicyId) {
    
            write-host "No Compliance Policy Id specified, specify a valid Compliance Policy Id" -f Red
            break
    
        }
    
        if (!$ComplianceAssignments) {

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
                
        }
    
        $JSON = @"

{
    "Assignments": [
        $ComplianceAssignments
    ]
}
"@

        Write-Output $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
        
    
    }
        
    catch {
    
        $ex = $_.Exception
        

        Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
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

write-host

if ($null -eq $User -or $User -eq "") {

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

}

Test-MgAuth -User $User

#endregion

####################################################

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"', '')

if (!(Test-Path "$ImportPath")) {

    Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

####################################################

Get-ChildItem $ImportPath -filter *.json |
Foreach-object {

    $JSON_Data = Get-Content $_.FullName | Where-Object { $_ -notmatch "scheduledActionConfigurations@odata.context" }

    # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
    $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, scheduledActionsForRule@odata.context

    $DisplayName = $JSON_Convert.displayName

    $DuplicateDCP = Get-DeviceCompliancePolicy -Name $JSON_Convert.displayName

    #write-host $DuplicateCA

    If ($null -eq $DuplicateDCP) {

        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 10


        # Adding Scheduled Actions Rule to JSON
        #$scheduledActionsForRule = '"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]'        

        #$JSON_Output = $JSON_Output.trimend("}")

        #$JSON_Output = $JSON_Output.TrimEnd() + "," + "`r`n"

        # Joining the JSON together
        #$JSON_Output = $JSON_Output + $scheduledActionsForRule + "`r`n" + "}"
            
        write-host
        write-host "Device Configuration Policy '$DisplayName' Found..." -ForegroundColor Yellow
        write-host
        $JSON_Output
        write-host
        Write-Host "Adding Device Configuration Policy '$DisplayName'" -ForegroundColor Yellow

        Add-DeviceCompliancePolicy -JSON $JSON_Output

        $DCPProfile = Get-DeviceCompliancePolicy -name $DisplayName

        $CompliancePolicyId = $DCPProfile.id

        Write-Host "Device Configuration Policy ID '$CompliancePolicyId'" -ForegroundColor Yellow
        Write-Host
        $AADGroups = $JSON_Convert.assignments.target

        $ComplianceAssignments = @()

        foreach ($AADGroup in $AADGroups ) 

        {
            Write-Host "AAD Group Name:" $AADGroup.groupId -ForegroundColor Yellow
            Write-Host "Assignment Type:" $AADGroup."@OData.type" -ForegroundColor Yellow
            $TargetGroupId = (Get-AADGroup -GroupName $AADGroup.groupid)
            $TargetGroupId = $TargetGroupId.id
            Write-Host "Included Group ID:" $TargetGroupID -ForegroundColor Yellow

            $Assignment = $AADGroup."@OData.type"                           
            $GroupAdd = @"
     {
            "target": {
            "@odata.type": "$Assignment",
            "groupId": "$TargetGroupId"
                        }
       },

"@
                
            $ComplianceAssignments += $GroupAdd
        }
               
        Add-DeviceCompliancePolicyAssignment -ComplianceAssignments $ComplianceAssignments -CompliancePolicyId $CompliancePolicyId
                  
    }          

    else 
    {
        write-host "Device Compliance Policy:" $JSON_Convert.displayName "has already been created" -ForegroundColor Yellow
    }

}   
