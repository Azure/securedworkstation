<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.
#>

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$ImportPath = $ScriptDir + "\JSON\DeviceConfiguration"

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
        if ($null -eq $User -or $User -eq "") {
            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host
        }
        $global:authToken = Get-AuthToken -User $User
    }
}
# Authentication doesn't exist, calling Get-AuthToken function
else {
    if ($null -eq $User -or $User -eq "") {
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    }
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
}
#endregion

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"', '')
if (!(Test-Path $ImportPath)) {
    Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break
}
####################################################
Get-ChildItem $ImportPath -filter *.json |
    Foreach-object {
        $JSON_Data = Get-Content $_.FullName

        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
        $DisplayName = $JSON_Convert.displayName
        
        $DuplicateDCP = Get-DeviceConfigurationPolicy -Name $JSON_Convert.displayName
        
        If ($DuplicateDCP -eq $null) {
            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5            
            write-host
            write-host "Device Configuration Policy '$DisplayName' Found..." -ForegroundColor Yellow
            write-host
            $JSON_Output
            write-host
            Write-Host "Adding Device Configuration Policy '$DisplayName'" -ForegroundColor Yellow

            Add-DeviceConfigurationPolicy -JSON $JSON_Output

            $DeviceConfigs = Get-DeviceConfigurationPolicy -name $DisplayName
            $DeviceConfigID = $DeviceConfigs.id
            Write-Host "Device ConfigID '$DeviceConfigID'" -ForegroundColor Yellow 
            Write-Host
            $AADGroups = $JSON_Convert.assignments.target
            foreach ($AADGroup in $AADGroups) {
                Write-Host "AAD Group Name:" $AADGroup.groupId -ForegroundColor Yellow
                Write-Host "Assignment Type:" $AADGroup."@OData.type" -ForegroundColor Yellow
        
                $TargetGroupId = (Get-AADGroup -GroupName $AADGroup.groupid)
                Write-Host "Included Group ID:" $TargetGroupID.Id -ForegroundColor Yellow
                Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DeviceConfigID -TargetGroupId $TargetGroupId.id -Assignment $AADGroup."@OData.type" 
            }
        }        
        else {
            write-host "Device Configuration Profile:" $JSON_Convert.displayName "has already been created" -ForegroundColor Yellow
        }
}