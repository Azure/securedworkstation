<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

param (

	#Change Conditional Access State, default is disabled
	#Options: enabled, disabled, enabledForReportingButNotEnforced
	[String]$AADGroup = "Privileged Workstations"
    
)

#$AADGroup = "PAW-Global-Devices"
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$ImportPath = $ScriptDir + "\JSON\DeviceConfigurationADMX"

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
	
Function Create-GroupPolicyConfigurations() {
		
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
		
	[cmdletbinding()]
	param
	(
		$DisplayName
	)
		
	$jsonCode = @"
{
    "description":"",
    "displayName":"$($DisplayName)"
}
"@
		
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations"
	Write-Verbose "Resource: $DCP_resource"
		
	try {
			
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		$responseBody = Invoke-MgGraphRequest -Uri $uri -Method Post -Body $jsonCode -ContentType "application/json"
			
			
	}
		
	catch {
			
		$ex = $_.Exception
        

		Write-Host "Response content:`n$($ex.Response.Content.ReadAsStringAsync().Result)" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
			
	}
	$responseBody.id
}
	
	
Function Create-GroupPolicyConfigurationsDefinitionValues() {
		
	<#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
		
	[cmdletbinding()]
	Param (
			
		[string]$GroupPolicyConfigurationID,
		$JSON
			
	)
		
	$graphApiVersion = "Beta"
		
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfigurationID)/definitionValues"
	write-host $DCP_resource
	try {
		if ($JSON -eq "" -or $null -eq $JSON) {
				
			write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red
				
		}
			
		else {
				
			Test-JSON -JSON $JSON
				
			$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
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

Function Get-GroupPolicyConfigurations() {
	
	<#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-GroupPolicyConfigurations
#>
	
	[cmdletbinding()]

	param
	(
		$name
	)

	
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations"
	
	try {
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get).Value | Where-Object { ($_.'displayName') -eq ("$Name") }
		
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

Function Add-GroupPolicyConfigurationPolicyAssignment() {

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

	[cmdletbinding()]

	param
	(
		$ConfigurationPolicyId,
		$TargetGroupId,
		$Assignment
	)

	$graphApiVersion = "Beta"
	$Resource = "deviceManagement/groupPolicyConfigurations/$ConfigurationPolicyId/assignments"
    
	try {

		if (!$ConfigurationPolicyId) {

			write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
			break

		}

		if (!$TargetGroupId) {

			write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
			break
        
		}
		if (!$Assignment) {

			write-host "No Assignment Type specified, specify a valid Assignment Type" -f Red
			break
		}

		# $ConfPolAssign = "$ConfigurationPolicyId" + "_" + "$TargetGroupId"


		$JSON = @"

        {
    "target": {
    "@odata.type": "#microsoft.graph.$Assignment",
    "groupId": "$TargetGroupId"
                }
        }
"@

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
	
# Defining User Principal Name if not present
if ($null -eq $User -or $User -eq "") {
			
	$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
	Write-Host
}
		
# Getting the authorization token
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


$TargetGroupId = (Get-AADGroup | Where-Object { $_.displayName -eq $AADGroup }).id

if ($null -eq $TargetGroupId -or $TargetGroupId -eq "") {

	Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
	Write-Host
	exit

}

####################################################



Get-ChildItem $ImportPath -filter *.json |  

ForEach-Object {

	$Policy_Name = $_.Name
	$Policy_Name = $Policy_Name.Substring(0, $Policy_Name.Length - 5)
	
	$DuplicateDCP = Get-GroupPolicyConfigurations -Name $Policy_Name

	If ($DuplicateDCP -eq $null) 
 {

		$GroupPolicyConfigurationID = Create-GroupPolicyConfigurations -DisplayName $Policy_Name
		$JSON_Data = Get-Content $_.FullName
		$JSON_Convert = $JSON_Data | ConvertFrom-Json
		$JSON_Convert | ForEach-Object { $_
    
			$JSON_Output = Convertto-Json -Depth 5 $_

			Write-Host $JSON_Output
			Create-GroupPolicyConfigurationsDefinitionValues -JSON $JSON_Output -GroupPolicyConfigurationID $GroupPolicyConfigurationID 
		}
		Write-Host "####################################################################################################" -ForegroundColor Green
		Write-Host "Policy: " $Policy_Name "created" -ForegroundColor Green
		Write-Host "####################################################################################################" -ForegroundColor Green

		$DeviceConfigs = Get-GroupPolicyConfigurations -name $Policy_Name

		$DeviceConfigID = $DeviceConfigs.id
	
		Add-GroupPolicyConfigurationPolicyAssignment -ConfigurationPolicyId $DeviceConfigID -TargetGroupId $TargetGroupId -Assignment "groupAssignmentTarget"
	}

	else 
 {
		write-host "Device Configuration ADMX Profile:" $Policy_Name "has already been created" -ForegroundColor Yellow
	}

}

