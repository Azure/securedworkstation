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
	
#region Authentication
	
write-host
	
# Checking if authToken exists before running authentication
if ($global:authToken) {
		
	# Setting DateTime to Universal time to work in all timezones
	$DateTime = (Get-Date).ToUniversalTime()
		
	# If the authToken exists checking when it expires
	$TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
		
	if ($TokenExpires -le 0) {
			
		write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
		write-host
			
		# Defining User Principal Name if not present
			
		if ($User -eq $null -or $User -eq "") {
				
			$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
			Write-Host
				
		}
			
		$global:authToken = Get-AuthToken -User $User
			
	}
}
	
# Authentication doesn't exist, calling Get-AuthToken function
	
else {
		
	if ($User -eq $null -or $User -eq "") {
			
		$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
		Write-Host
			
	}
		
	# Getting the authorization token
	$global:authToken = Get-AuthToken -User $User
		
}
	
#endregion

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"', '')
if (!(Test-Path "$ImportPath")) {
	Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
	Write-Host "Script can't continue..." -ForegroundColor Red
	Write-Host
	break		
}

$TargetGroupId = (Get-AADGroup | Where-Object { $_.displayName -eq $AADGroup }).id
if ($null -eq $TargetGroupId -or $TargetGroupId -eq "") {
	Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
	Write-Host
	exit
}

Get-ChildItem $ImportPath -filter *.json |  
	ForEach-Object {
		$Policy_Name = $_.Name
		$Policy_Name = $Policy_Name.Substring(0, $Policy_Name.Length - 5)	
		$DuplicateDCP = Get-GroupPolicyConfigurations -Name $Policy_Name
		if ($DuplicateDCP -eq $null){
			$GroupPolicyConfigurationID = Create-GroupPolicyConfigurations -DisplayName $Policy_Name
			$JSON_Data = Get-Content $_.FullName
			$JSON_Convert = $JSON_Data | ConvertFrom-Json
			$JSON_Convert | 
				ForEach-Object { $_    
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
		else{
			write-host "Device Configuration ADMX Profile:" $Policy_Name "has already been created" -ForegroundColor Yellow
		}
	}