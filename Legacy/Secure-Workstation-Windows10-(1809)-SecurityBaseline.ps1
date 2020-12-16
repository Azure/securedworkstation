<##################################################################################################
#
.SYNOPSIS
This is a script steps up the secure workstation enforcement. It moves the Enhanced baseline to full blocking security model
It is recommended to use the Ehanced baselie, and the 
DeviceConfiguration_NCSC Baseline: https://www.ncsc.gov.uk/guidance/eud-guidance-windows-10-1803-mobile-device-management 
prior to enabling this set of controls. THESE CONTROLS ARE EXTREAMLY RESTRICTIVE TO THE HOST.


.NOTES
    FileName:    Secure Workstation - Windows10 (1809) SecurityBaseline.ps1
    Author:      Per Larsen 
	Revised:     Frank Simorjay
    Created:     03-09-2018
	Revised:     05-09-2019
    Version:     1.1 hardended
    
#>
###################################################################################################
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Add-DeviceConfigurationPolicy(){

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
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Test-JSON(){

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

    if (!$validJson){

    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break

    }

}


####################################################

Function Add-DeviceCompliancePolicybaseline(){

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
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
            }
    
        }
        
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }
    
    ####################################################
####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){
           $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){
    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion


####################################################
#Jason Components
####################################################
$Applocker = @"

{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "id":  "3885eed4-a552-46d4-876b-eadbbcf1ef83",
    "createdDateTime":  "2019-03-01T11:16:41.0845229Z",
    "description":  "AppLocker configuration for Secure Workstation",
    "displayName":  "AppLocker configuration for Secure Workstation",
    "version":  1,
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingStringXml",
                            "displayName":  "AppLocker Store Apps",
                            "description":  "AppLocker configuration for inbox Microsoft store applications ",
                            "omaUri":  "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/StoreAppsGroup/StoreApps/Policy",
                            "fileName":  "AppLocker Appx.xml",
                            "value":  "ICA8UnVsZUNvbGxlY3Rpb24gVHlwZT0iQXBweCIgRW5mb3JjZW1lbnRNb2RlPSJFbmFibGVkIj4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjViMmE4NDc3LTU2MTctNDY1My1iYWRkLTgxZWUyM2ZjMmJiNiIgTmFtZT0iQWxsIHNpZ25lZCBwYWNrYWdlZCBhcHBzIiBEZXNjcmlwdGlvbj0iQWxsb3dzIG1lbWJlcnMgb2YgdGhlIEV2ZXJ5b25lIGdyb3VwIHRvIHJ1biBwYWNrYWdlZCBhcHBzIHRoYXQgYXJlIHNpZ25lZC4iIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSIqIiBQcm9kdWN0TmFtZT0iKiIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIwLjAuMC4wIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgICAgPEV4Y2VwdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9IkNOPU1pY3Jvc29mdCBDb3Jwb3JhdGlvbiwgTz1NaWNyb3NvZnQgQ29ycG9yYXRpb24sIEw9UmVkbW9uZCwgUz1XYXNoaW5ndG9uLCBDPVVTIiBQcm9kdWN0TmFtZT0iTWljcm9zb2Z0LkdldHN0YXJ0ZWQiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMi4xLjAuMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iQ049TWljcm9zb2Z0IENvcnBvcmF0aW9uLCBPPU1pY3Jvc29mdCBDb3Jwb3JhdGlvbiwgTD1SZWRtb25kLCBTPVdhc2hpbmd0b24sIEM9VVMiIFByb2R1Y3ROYW1lPSJNaWNyb3NvZnQuTWljcm9zb2Z0T2ZmaWNlSHViIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE3LjQyMTguMC4wIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJDTj1Ta3lwZSBTb2Z0d2FyZSBTYXJsLCBPPU1pY3Jvc29mdCBDb3Jwb3JhdGlvbiwgTD1MdXhlbWJvdXJnLCBTPUx1eGVtYm91cmcsIEM9TFUiIFByb2R1Y3ROYW1lPSJNaWNyb3NvZnQuU2t5cGVBcHAiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMy4yLjAuMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iQ049TWljcm9zb2Z0IFdpbmRvd3MsIE89TWljcm9zb2Z0IENvcnBvcmF0aW9uLCBMPVJlZG1vbmQsIFM9V2FzaGluZ3RvbiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1pY3Jvc29mdC5XaW5kb3dzRmVlZGJhY2siIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTAuMC4wLjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0V4Y2VwdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgPC9SdWxlQ29sbGVjdGlvbj4="
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingStringXml",
                            "displayName":  "AppLocker EXE",
                            "description":  "AppLocker configuration for inbox executables",
                            "omaUri":  "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/EXEGroup/EXE/Policy",
                            "fileName":  "AppLocker EXE.xml",
                            "value":  "ICA8UnVsZUNvbGxlY3Rpb24gVHlwZT0iRXhlIiBFbmZvcmNlbWVudE1vZGU9IkVuYWJsZWQiPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9IjM2NTg5YTdlLTRhYzYtNGJmMC1hYWI5LTFhODdhNDY5YzdkMiIgTmFtZT0iQWxsIGZpbGVzIGxvY2F0ZWQgaW4gdGhlIFByb2dyYW0gRmlsZXMgZm9sZGVyIiBEZXNjcmlwdGlvbj0iQWxsb3dzIG1lbWJlcnMgb2YgdGhlIEV2ZXJ5b25lIGdyb3VwIHRvIHJ1biBhcHBsaWNhdGlvbnMgdGhhdCBhcmUgbG9jYXRlZCBpbiB0aGUgUHJvZ3JhbSBGaWxlcyBmb2xkZXIuIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVQUk9HUkFNRklMRVMlXCoiIC8+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgICA8RXhjZXB0aW9ucz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVQUk9HUkFNRklMRVMlXFdpbmRvd3MgS2l0c1wqXERlYnVnZ2Vyc1wqIiAvPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9IjVjMmE5MjZkLWFhMDctNDFlZS04MTk5LTI5MzNhMGUwNTk3OSIgTmFtZT0iQWxsIGZpbGVzIGxvY2F0ZWQgaW4gdGhlIFdpbmRvd3MgZm9sZGVyIC0gd2l0aCBleGNlcHRpb25zIiBEZXNjcmlwdGlvbj0iQWxsb3dzIG1lbWJlcnMgb2YgdGhlIEV2ZXJ5b25lIGdyb3VwIHRvIHJ1biBhcHBsaWNhdGlvbnMgdGhhdCBhcmUgbG9jYXRlZCBpbiB0aGUgV2luZG93cyBmb2xkZXIuIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXCoiIC8+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgICA8RXhjZXB0aW9ucz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVTWVNURU0zMiVcY29tXGRtcFwqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxGeHNUbXBcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVTWVNURU0zMiVcTWljcm9zb2Z0XENyeXB0b1xSU0FcTWFjaGluZUtleXNcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVTWVNURU0zMiVcU3Bvb2xcZHJpdmVyc1xjb2xvclwqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxTcG9vbFxQUklOVEVSU1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxTcG9vbFxTRVJWRVJTXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXFRhc2tzXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlV0lORElSJVxyZWdpc3RyYXRpb25cY3JtbG9nXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlV0lORElSJVxzZXJ2aWNpbmdcUGFja2FnZXNcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXHNlcnZpY2luZ1xTZXNzaW9uc1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcVGFza3NcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXHRlbXBcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXFRyYWNpbmdcKiIgLz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iSU5URVJORVQgRVhQTE9SRVIiIEJpbmFyeU5hbWU9Ik1TSFRBLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxMS4wLjAuMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUKFIpIENPTk5FQ1RJT04gTUFOQUdFUiIgQmluYXJ5TmFtZT0iQ01TVFAuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVMKuIC5ORVQgRlJBTUVXT1JLIiBCaW5hcnlOYW1lPSJJRUVYRUMuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjIuMC4wLjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVMKuIC5ORVQgRlJBTUVXT1JLIiBCaW5hcnlOYW1lPSJJTlNUQUxMVVRJTC5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMi4wLjAuMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUwq4gLk5FVCBGUkFNRVdPUksiIEJpbmFyeU5hbWU9Ik1TQlVJTEQuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjEuMC4wLjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVMKuIC5ORVQgRlJBTUVXT1JLIiBCaW5hcnlOYW1lPSJSRUdBU00uRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjEuMC4wLjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVMKuIC5ORVQgRlJBTUVXT1JLIiBCaW5hcnlOYW1lPSJSRUdTVkNTLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxLjAuMC4wIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlTCriBXSU5ET1dTwq4gT1BFUkFUSU5HIFNZU1RFTSIgQmluYXJ5TmFtZT0iQ0RCLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxLjAuMC4wIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlTCriBXSU5ET1dTwq4gT1BFUkFUSU5HIFNZU1RFTSIgQmluYXJ5TmFtZT0iQ0lQSEVSLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIqIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlTCriBXSU5ET1dTwq4gT1BFUkFUSU5HIFNZU1RFTSIgQmluYXJ5TmFtZT0iUFJFU0VOVEFUSU9OSE9TVC5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUwq4gV0lORE9XU8KuIE9QRVJBVElORyBTWVNURU0iIEJpbmFyeU5hbWU9IldJTkRCRy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMS4wLjAuMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUwq4gV0lORE9XU8KuIE9QRVJBVElORyBTWVNURU0iIEJpbmFyeU5hbWU9IldNSUMuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0V4Y2VwdGlvbnM+DQogICAgPC9GaWxlUGF0aFJ1bGU+DQogICAgPEZpbGVQYXRoUnVsZSBJZD0iYWJiZjdiMWUtZTRjZS00NmFlLTlhYjMtY2EwNDRlMWYwMDc5IiBOYW1lPSIlT1NEUklWRSVcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XFdpbmRvd3MgRGVmZW5kZXJcUGxhdGZvcm1cKiIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlT1NEUklWRSVcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XFdpbmRvd3MgRGVmZW5kZXJcUGxhdGZvcm1cKiIgLz4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQYXRoUnVsZT4NCiAgICA8RmlsZVBhdGhSdWxlIElkPSJmZDY4NmQ4My1hODI5LTQzNTEtOGZmNC0yN2M3ZGU1NzU1ZDIiIE5hbWU9IihEZWZhdWx0IFJ1bGUpIEFsbCBmaWxlcyIgRGVzY3JpcHRpb249IkFsbG93cyBtZW1iZXJzIG9mIHRoZSBsb2NhbCBBZG1pbmlzdHJhdG9ycyBncm91cCB0byBydW4gYWxsIGFwcGxpY2F0aW9ucy4iIFVzZXJPckdyb3VwU2lkPSJTLTEtNS0zMi01NDQiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIqIiAvPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICA8L1J1bGVDb2xsZWN0aW9uPg=="
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingStringXml",
                            "displayName":  "AppLocker MSI",
                            "description":  "AppLocker configuration for inbox MSIs",
                            "omaUri":  "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/MSIGroup/MSI/Policy",
                            "fileName":  "AppLocker MSI.xml",
                            "value":  "ICA8UnVsZUNvbGxlY3Rpb24gVHlwZT0iTXNpIiBFbmZvcmNlbWVudE1vZGU9IkVuYWJsZWQiPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9IjY0YWQ0NmZmLTBkNzEtNGZhMC1hMzBiLTNmM2QzMGM1NDMzZCIgTmFtZT0iKERlZmF1bHQgUnVsZSkgQWxsIFdpbmRvd3MgSW5zdGFsbGVyIGZpbGVzIiBEZXNjcmlwdGlvbj0iQWxsb3dzIG1lbWJlcnMgb2YgdGhlIGxvY2FsIEFkbWluaXN0cmF0b3JzIGdyb3VwIHRvIHJ1biBhbGwgV2luZG93cyBJbnN0YWxsZXIgZmlsZXMuIiBVc2VyT3JHcm91cFNpZD0iUy0xLTUtMzItNTQ0IiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iKi4qIiAvPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9ImRiZDhmZjllLWE2NzAtNGUzYi1iNTllLWMwY2QzOTYzN2I5OSIgTmFtZT0iJVdJTkRJUiVcSW5zdGFsbGVyXCoiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcSW5zdGFsbGVyXCoiIC8+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUGF0aFJ1bGU+DQogIDwvUnVsZUNvbGxlY3Rpb24+"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingStringXml",
                            "displayName":  "AppLocker Script",
                            "description":  "AppLocker Configuration for inbox scripts",
                            "omaUri":  "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/ScriptGroup/Script/Policy",
                            "fileName":  "AppLocker Script.xml",
                            "value":  "ICA8UnVsZUNvbGxlY3Rpb24gVHlwZT0iU2NyaXB0IiBFbmZvcmNlbWVudE1vZGU9IkVuYWJsZWQiPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9IjA2ZGNlNjdiLTkzNGMtNDU0Zi1hMjYzLTI1MTVjODc5NmE1ZCIgTmFtZT0iKERlZmF1bHQgUnVsZSkgQWxsIHNjcmlwdHMgbG9jYXRlZCBpbiB0aGUgUHJvZ3JhbSBGaWxlcyBmb2xkZXIiIERlc2NyaXB0aW9uPSJBbGxvd3MgbWVtYmVycyBvZiB0aGUgRXZlcnlvbmUgZ3JvdXAgdG8gcnVuIHNjcmlwdHMgdGhhdCBhcmUgbG9jYXRlZCBpbiB0aGUgUHJvZ3JhbSBGaWxlcyBmb2xkZXIuIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVQUk9HUkFNRklMRVMlXCoiIC8+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUGF0aFJ1bGU+DQogICAgPEZpbGVQYXRoUnVsZSBJZD0iNDQyNGVjN2MtYzZmZi00MDE1LWJhNmEtN2Y0NjU4MDhkYjIxIiBOYW1lPSJBbGwgc2NyaXB0cyBsb2NhdGVkIGluIHRoZSBXaW5kb3dzIGZvbGRlciIgRGVzY3JpcHRpb249IkFsbG93cyBtZW1iZXJzIG9mIHRoZSBFdmVyeW9uZSBncm91cCB0byBydW4gc2NyaXB0cyB0aGF0IGFyZSBsb2NhdGVkIGluIHRoZSBXaW5kb3dzIGZvbGRlci4iIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcKiIgLz4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxjb21cZG1wXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXEZ4c1RtcFwqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxNaWNyb3NvZnRcQ3J5cHRvXFJTQVxNYWNoaW5lS2V5c1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxTcG9vbFxkcml2ZXJzXGNvbG9yXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXFNwb29sXFBSSU5URVJTXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXFNwb29sXFNFUlZFUlNcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVTWVNURU0zMiVcVGFza3NcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXHJlZ2lzdHJhdGlvblxjcm1sb2dcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXHNlcnZpY2luZ1xQYWNrYWdlc1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcc2VydmljaW5nXFNlc3Npb25zXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlV0lORElSJVxUYXNrc1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcdGVtcFwqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcVHJhY2luZ1wqIiAvPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9ImVkOTdkMGNiLTE1ZmYtNDMwZi1iODJjLThkNzgzMjk1NzcyNSIgTmFtZT0iKERlZmF1bHQgUnVsZSkgQWxsIHNjcmlwdHMiIERlc2NyaXB0aW9uPSJBbGxvd3MgbWVtYmVycyBvZiB0aGUgbG9jYWwgQWRtaW5pc3RyYXRvcnMgZ3JvdXAgdG8gcnVuIGFsbCBzY3JpcHRzLiIgVXNlck9yR3JvdXBTaWQ9IlMtMS01LTMyLTU0NCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IioiIC8+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUGF0aFJ1bGU+DQogIDwvUnVsZUNvbGxlY3Rpb24+"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingStringXml",
                            "displayName":  "AppLocker DLL",
                            "description":  "AppLocker configuration for inbox DLLs",
                            "omaUri":  "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/DLLGroup/DLL/Policy",
                            "fileName":  "AppLocker DLL.xml",
                            "value":  "ICA8UnVsZUNvbGxlY3Rpb24gVHlwZT0iRGxsIiBFbmZvcmNlbWVudE1vZGU9IkVuYWJsZWQiPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9IjM3Mzc3MzJjLTk5YjctNDFkNC05MDM3LTljZGRmYjBkZTBkMCIgTmFtZT0iKERlZmF1bHQgUnVsZSkgQWxsIERMTHMgbG9jYXRlZCBpbiB0aGUgUHJvZ3JhbSBGaWxlcyBmb2xkZXIiIERlc2NyaXB0aW9uPSJBbGxvd3MgbWVtYmVycyBvZiB0aGUgRXZlcnlvbmUgZ3JvdXAgdG8gbG9hZCBETExzIHRoYXQgYXJlIGxvY2F0ZWQgaW4gdGhlIFByb2dyYW0gRmlsZXMgZm9sZGVyLiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlUFJPR1JBTUZJTEVTJVwqIiAvPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9ImIzMjI4NjlmLTc0MzEtNDg4Yy1hYjBkLWUxYzQ5NTEwMjgzZiIgTmFtZT0iJU9TRFJJVkUlXFByb2dyYW1EYXRhXE1pY3Jvc29mdFxXaW5kb3dzIERlZmVuZGVyXFBsYXRmb3JtXCoiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJU9TRFJJVkUlXFByb2dyYW1EYXRhXE1pY3Jvc29mdFxXaW5kb3dzIERlZmVuZGVyXFBsYXRmb3JtXCoiIC8+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUGF0aFJ1bGU+DQogICAgPEZpbGVQYXRoUnVsZSBJZD0iZTBlMWY0NTQtZDYzZS00MWNiLTg1ZDUtM2MxMWE5Yjk4ODlmIiBOYW1lPSJNaWNyb3NvZnQgV2luZG93cyBETExzIC0gd2l0aCBleGNlcHRpb25zIGZvciB3cml0ZWFibGUgbG9jYXRpb25zIiBEZXNjcmlwdGlvbj0iQWxsb3dzIG1lbWJlcnMgb2YgdGhlIEV2ZXJ5b25lIGdyb3VwIHRvIGxvYWQgRExMcyBsb2NhdGVkIGluIHRoZSBXaW5kb3dzIGZvbGRlci4iIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcKiIgLz4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxjb21cZG1wXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXEZ4c1RtcFwqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxNaWNyb3NvZnRcQ3J5cHRvXFJTQVxNYWNoaW5lS2V5c1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVNZU1RFTTMyJVxTcG9vbFxkcml2ZXJzXGNvbG9yXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXFNwb29sXFBSSU5URVJTXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlU1lTVEVNMzIlXFNwb29sXFNFUlZFUlNcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVTWVNURU0zMiVcVGFza3NcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXHJlZ2lzdHJhdGlvblxjcm1sb2dcKiIgLz4NCiAgICAgICAgPEZpbGVQYXRoQ29uZGl0aW9uIFBhdGg9IiVXSU5ESVIlXHNlcnZpY2luZ1xQYWNrYWdlc1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcc2VydmljaW5nXFNlc3Npb25zXCoiIC8+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIlV0lORElSJVxUYXNrc1wqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcdGVtcFwqIiAvPg0KICAgICAgICA8RmlsZVBhdGhDb25kaXRpb24gUGF0aD0iJVdJTkRJUiVcVHJhY2luZ1wqIiAvPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICAgIDxGaWxlUGF0aFJ1bGUgSWQ9ImZlNjRmNTlmLTZmY2EtNDVlNS1hNzMxLTBmNjcxNTMyN2MzOCIgTmFtZT0iKERlZmF1bHQgUnVsZSkgQWxsIERMTHMiIERlc2NyaXB0aW9uPSJBbGxvd3MgbWVtYmVycyBvZiB0aGUgbG9jYWwgQWRtaW5pc3RyYXRvcnMgZ3JvdXAgdG8gbG9hZCBhbGwgRExMcy4iIFVzZXJPckdyb3VwU2lkPSJTLTEtNS0zMi01NDQiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUGF0aENvbmRpdGlvbiBQYXRoPSIqIiAvPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVBhdGhSdWxlPg0KICA8L1J1bGVDb2xsZWN0aW9uPg=="
                        }
                    ]
}

"@

####################################################


$firewall = @"


{
    "@odata.type":  "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "createdDateTime":  "2019-04-30T22:04:19.2180497Z",
    "description":  "Firewall configuration for Secure Workstation",
    "displayName":  "Firewall configuration for Secure Workstation",
    "version":  3,
    "dmaGuardDeviceEnumerationPolicy":  "deviceDefault",
    "userRightsAccessCredentialManagerAsTrustedCaller":  null,
    "userRightsAllowAccessFromNetwork":  null,
    "userRightsBlockAccessFromNetwork":  null,
    "userRightsActAsPartOfTheOperatingSystem":  null,
    "userRightsLocalLogOn":  null,
    "userRightsBackupData":  null,
    "userRightsChangeSystemTime":  null,
    "userRightsCreateGlobalObjects":  null,
    "userRightsCreatePageFile":  null,
    "userRightsCreatePermanentSharedObjects":  null,
    "userRightsCreateSymbolicLinks":  null,
    "userRightsCreateToken":  null,
    "userRightsDebugPrograms":  null,
    "userRightsRemoteDesktopServicesLogOn":  null,
    "userRightsDelegation":  null,
    "userRightsGenerateSecurityAudits":  null,
    "userRightsImpersonateClient":  null,
    "userRightsIncreaseSchedulingPriority":  null,
    "userRightsLoadUnloadDrivers":  null,
    "userRightsLockMemory":  null,
    "userRightsManageAuditingAndSecurityLogs":  null,
    "userRightsManageVolumes":  null,
    "userRightsModifyFirmwareEnvironment":  null,
    "userRightsModifyObjectLabels":  null,
    "userRightsProfileSingleProcess":  null,
    "userRightsRemoteShutdown":  null,
    "userRightsRestoreData":  null,
    "userRightsTakeOwnership":  null,
    "userRightsRegisterProcessAsService":  null,
    "xboxServicesEnableXboxGameSaveTask":  false,
    "xboxServicesAccessoryManagementServiceStartupMode":  "disabled",
    "xboxServicesLiveAuthManagerServiceStartupMode":  "disabled",
    "xboxServicesLiveGameSaveServiceStartupMode":  "disabled",
    "xboxServicesLiveNetworkingServiceStartupMode":  "disabled",
    "localSecurityOptionsBlockMicrosoftAccounts":  true,
    "localSecurityOptionsBlockRemoteLogonWithBlankPassword":  true,
    "localSecurityOptionsDisableAdministratorAccount":  true,
    "localSecurityOptionsAdministratorAccountName":  "administrator",
    "localSecurityOptionsDisableGuestAccount":  true,
    "localSecurityOptionsGuestAccountName":  "guest01",
    "localSecurityOptionsAllowUndockWithoutHavingToLogon":  true,
    "localSecurityOptionsBlockUsersInstallingPrinterDrivers":  true,
    "localSecurityOptionsBlockRemoteOpticalDriveAccess":  true,
    "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser":  "notConfigured",
    "localSecurityOptionsMachineInactivityLimit":  15,
    "localSecurityOptionsMachineInactivityLimitInMinutes":  15,
    "localSecurityOptionsDoNotRequireCtrlAltDel":  true,
    "localSecurityOptionsHideLastSignedInUser":  true,
    "localSecurityOptionsHideUsernameAtSignIn":  true,
    "localSecurityOptionsLogOnMessageTitle":  "Welcome to Azure Secure Workstation",
    "localSecurityOptionsLogOnMessageText":  "Restricted device for managing Azure services",
    "localSecurityOptionsAllowPKU2UAuthenticationRequests":  true,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool":  true,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager":  null,
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients":  "ntlmV2And128BitEncryption",
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers":  "ntlmV2And128BitEncryption",
    "lanManagerAuthenticationLevel":  "lmNtlmV2AndNotLmOrNtm",
    "lanManagerWorkstationDisableInsecureGuestLogons":  true,
    "localSecurityOptionsClearVirtualMemoryPageFile":  true,
    "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn":  false,
    "localSecurityOptionsAllowUIAccessApplicationElevation":  true,
    "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations":  true,
    "localSecurityOptionsOnlyElevateSignedExecutables":  true,
    "localSecurityOptionsAdministratorElevationPromptBehavior":  "promptForCredentials",
    "localSecurityOptionsStandardUserElevationPromptBehavior":  "automaticallyDenyElevationRequests",
    "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation":  true,
    "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation":  true,
    "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations":  true,
    "localSecurityOptionsUseAdminApprovalMode":  true,
    "localSecurityOptionsUseAdminApprovalModeForAdministrators":  true,
    "localSecurityOptionsInformationShownOnLockScreen":  "userDisplayNameDomainUser",
    "localSecurityOptionsInformationDisplayedOnLockScreen":  "administrators",
    "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees":  false,
    "localSecurityOptionsClientDigitallySignCommunicationsAlways":  true,
    "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers":  true,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways":  true,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees":  false,
    "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares":  true,
    "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts":  true,
    "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares":  true,
    "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange":  true,
    "localSecurityOptionsSmartCardRemovalBehavior":  "noAction",
	"defenderDisableScanArchiveFiles":  false,
    "defenderDisableBehaviorMonitoring":  false,
    "defenderDisableCloudProtection":  false,
    "defenderEnableScanIncomingMail":  true,
    "defenderEnableScanMappedNetworkDrivesDuringFullScan":  true,
    "defenderDisableScanRemovableDrivesDuringFullScan":  false,
    "defenderDisableScanDownloads":  false,
    "defenderDisableIntrusionPreventionSystem":  false,
    "defenderDisableOnAccessProtection":  false,
    "defenderDisableRealTimeMonitoring":  false,
    "defenderDisableScanNetworkFiles":  false,
    "defenderDisableScanScriptsLoadedInInternetExplorer":  false,
    "defenderBlockEndUserAccess":  true,
    "defenderCheckForSignaturesBeforeRunningScan":  false,
    "defenderCloudBlockLevel":  "high",
    "defenderDisableCatchupFullScan":  false,
    "defenderDisableCatchupQuickScan":  false,
    "defenderEnableLowCpuPriority":  false,
    "defenderPotentiallyUnwantedAppAction":  "enable",
    "defenderScanDirection":  "0",
    "defenderScanType":  "2",
    "defenderScheduledScanDay":  "0",
    "defenderSubmitSamplesConsentType":  "0",
    "defenderSecurityCenterDisableAppBrowserUI":  true,
    "defenderSecurityCenterDisableFamilyUI":  true,
    "defenderSecurityCenterDisableHealthUI":  true,
    "defenderSecurityCenterDisableNetworkUI":  true,
    "defenderSecurityCenterDisableVirusUI":  false,
    "defenderSecurityCenterDisableAccountUI":  true,
    "defenderSecurityCenterDisableClearTpmUI":  true,
    "defenderSecurityCenterDisableHardwareUI":  true,
    "defenderSecurityCenterDisableNotificationAreaUI":  false,
    "defenderSecurityCenterDisableRansomwareUI":  false,
    "defenderSecurityCenterDisableSecureBootUI":  false,
    "defenderSecurityCenterDisableTroubleshootingUI":  false,
    "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI":  true,
    "defenderSecurityCenterOrganizationDisplayName":  null,
    "defenderSecurityCenterHelpEmail":  null,
    "defenderSecurityCenterHelpPhone":  null,
    "defenderSecurityCenterHelpURL":  null,
    "defenderSecurityCenterNotificationsFromApp":  "blockNoncriticalNotifications",
    "defenderSecurityCenterITContactDisplay":  "notConfigured",
    "firewallBlockStatefulFTP":  true,
    "firewallIdleTimeoutForSecurityAssociationInSeconds":  null,
    "firewallPreSharedKeyEncodingMethod":  "deviceDefault",
    "firewallIPSecExemptionsAllowNeighborDiscovery":  true,
    "firewallIPSecExemptionsAllowICMP":  true,
    "firewallIPSecExemptionsAllowRouterDiscovery":  true,
    "firewallIPSecExemptionsAllowDHCP":  true,
    "firewallCertificateRevocationListCheckMethod":  "require",
    "firewallMergeKeyingModuleSettings":  false,
    "firewallPacketQueueingMethod":  "deviceDefault",
    "defenderAdobeReaderLaunchChildProcess":  "enable",
    "defenderAttackSurfaceReductionExcludedPaths":  [

                                                    ],
    "defenderOfficeAppsOtherProcessInjectionType":  "block",
    "defenderOfficeAppsOtherProcessInjection":  "enable",
    "defenderOfficeCommunicationAppsLaunchChildProcess":  "enable",
    "defenderOfficeAppsExecutableContentCreationOrLaunchType":  "block",
    "defenderOfficeAppsExecutableContentCreationOrLaunch":  "enable",
    "defenderOfficeAppsLaunchChildProcessType":  "block",
    "defenderOfficeAppsLaunchChildProcess":  "enable",
    "defenderOfficeMacroCodeAllowWin32ImportsType":  "block",
    "defenderOfficeMacroCodeAllowWin32Imports":  "enable",
    "defenderScriptObfuscatedMacroCodeType":  "block",
    "defenderScriptObfuscatedMacroCode":  "enable",
    "defenderScriptDownloadedPayloadExecutionType":  "block",
    "defenderScriptDownloadedPayloadExecution":  "enable",
    "defenderPreventCredentialStealingType":  "enable",
    "defenderProcessCreationType":  "block",
    "defenderProcessCreation":  "enable",
    "defenderUntrustedUSBProcessType":  "block",
    "defenderUntrustedUSBProcess":  "enable",
    "defenderUntrustedExecutableType":  "block",
    "defenderUntrustedExecutable":  "enable",
    "defenderEmailContentExecutionType":  "block",
    "defenderEmailContentExecution":  "enable",
    "defenderAdvancedRansomewareProtectionType":  "enable",
    "defenderGuardMyFoldersType":  "userDefined",
    "defenderGuardedFoldersAllowedAppPaths":  [

                                              ],
    "defenderAdditionalGuardedFolders":  [

                                         ],
    "defenderNetworkProtectionType":  "userDefined",
    "defenderExploitProtectionXml":  null,
    "defenderExploitProtectionXmlFileName":  null,
    "defenderSecurityCenterBlockExploitProtectionOverride":  false,
    "appLockerApplicationControl":  "enforceComponentsStoreAppsAndSmartlocker",
    "deviceGuardLocalSystemAuthorityCredentialGuardSettings":  "enableWithUEFILock",
    "deviceGuardEnableVirtualizationBasedSecurity":  true,
    "deviceGuardEnableSecureBootWithDMA":  true,
    "deviceGuardLaunchSystemGuard":  "notConfigured",
    "smartScreenEnableInShell":  true,
    "smartScreenBlockOverrideForFiles":  true,
    "applicationGuardEnabled":  true,
    "applicationGuardEnabledOptions":  "enabledForEdge",
    "applicationGuardBlockFileTransfer":  "notConfigured",
    "applicationGuardBlockNonEnterpriseContent":  true,
    "applicationGuardAllowPersistence":  false,
    "applicationGuardForceAuditing":  false,
    "applicationGuardBlockClipboardSharing":  "notConfigured",
    "applicationGuardAllowPrintToPDF":  true,
    "applicationGuardAllowPrintToXPS":  false,
    "applicationGuardAllowPrintToLocalPrinters":  true,
    "applicationGuardAllowPrintToNetworkPrinters":  true,
    "applicationGuardAllowVirtualGPU":  true,
    "applicationGuardAllowFileSaveOnHost":  true,
    "bitLockerAllowStandardUserEncryption":  false,
    "bitLockerDisableWarningForOtherDiskEncryption":  false,
    "bitLockerEnableStorageCardEncryptionOnMobile":  false,
    "bitLockerEncryptDevice":  false,
    "firewallRules":  [

                      ],
    "firewallProfileDomain":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  true,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  true,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  false,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  true
                              },
    "firewallProfilePublic":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  true,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  true,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  true,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  true,
                                  "outboundConnectionsRequired":  false,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePrivate":  {
                                   "firewallEnabled":  "allowed",
                                   "stealthModeRequired":  false,
                                   "stealthModeBlocked":  false,
                                   "incomingTrafficRequired":  false,
                                   "incomingTrafficBlocked":  false,
                                   "unicastResponsesToMulticastBroadcastsRequired":  false,
                                   "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                   "inboundNotificationsRequired":  false,
                                   "inboundNotificationsBlocked":  true,
                                   "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                   "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                   "globalPortRulesFromGroupPolicyMerged":  false,
                                   "globalPortRulesFromGroupPolicyNotMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                   "outboundConnectionsRequired":  false,
                                   "outboundConnectionsBlocked":  false,
                                   "inboundConnectionsRequired":  false,
                                   "inboundConnectionsBlocked":  true,
                                   "securedPacketExemptionAllowed":  false,
                                   "securedPacketExemptionBlocked":  false,
                                   "policyRulesFromGroupPolicyMerged":  false,
                                   "policyRulesFromGroupPolicyNotMerged":  true
                               },
    "bitLockerSystemDrivePolicy":  {
                                       "encryptionMethod":  "xtsAes256",
                                       "startupAuthenticationRequired":  true,
                                       "startupAuthenticationBlockWithoutTpmChip":  true,
                                       "startupAuthenticationTpmUsage":  "required",
                                       "startupAuthenticationTpmPinUsage":  "required",
                                       "startupAuthenticationTpmKeyUsage":  "required",
                                       "startupAuthenticationTpmPinAndKeyUsage":  "required",
                                       "minimumPinLength":  8,
                                       "prebootRecoveryEnableMessageAndUrl":  false,
                                       "prebootRecoveryMessage":  null,
                                       "prebootRecoveryUrl":  null,
                                       "recoveryOptions":  {
                                                               "blockDataRecoveryAgent":  false,
                                                               "recoveryPasswordUsage":  "required",
                                                               "recoveryKeyUsage":  "required",
                                                               "hideRecoveryOptions":  false,
                                                               "enableRecoveryInformationSaveToStore":  true,
                                                               "recoveryInformationToStore":  "passwordAndKey",
                                                               "enableBitLockerAfterRecoveryInformationToStore":  false
                                                           }
                                   },
    "bitLockerFixedDrivePolicy":  {
                                      "encryptionMethod":  "xtsAes256",
                                      "requireEncryptionForWriteAccess":  true,
                                      "recoveryOptions":  {
                                                              "blockDataRecoveryAgent":  true,
                                                              "recoveryPasswordUsage":  "required",
                                                              "recoveryKeyUsage":  "required",
                                                              "hideRecoveryOptions":  false,
                                                              "enableRecoveryInformationSaveToStore":  true,
                                                              "recoveryInformationToStore":  "passwordAndKey",
                                                              "enableBitLockerAfterRecoveryInformationToStore":  true
                                                          }
                                  },
    "bitLockerRemovableDrivePolicy":  {
                                          "encryptionMethod":  "xtsAes256",
                                          "requireEncryptionForWriteAccess":  true,
                                          "blockCrossOrganizationWriteAccess":  true
                                      }
}
"@

####################################################


$System1 = @"

{
    "@odata.type":  "#microsoft.graph.windows10GeneralConfiguration",
    "id":  "cc5056a0-41d7-4320-949d-58155fa08464",
    "createdDateTime":  "2019-03-01T14:38:52.2062303Z",
    "description":  "System Hardening configuration for Secure Workstation",
    "displayName":  "System Hardening configuration for Secure Workstation",
    "version":  1,
    "enableAutomaticRedeployment":  false,
    "assignedAccessSingleModeUserName":  null,
    "assignedAccessSingleModeAppUserModelId":  null,
    "microsoftAccountSignInAssistantSettings":  "notConfigured",
    "authenticationAllowSecondaryDevice":  false,
    "authenticationAllowFIDODevice":  true,
    "cryptographyAllowFipsAlgorithmPolicy":  false,
    "displayAppListWithGdiDPIScalingTurnedOn":  [

                                                ],
    "displayAppListWithGdiDPIScalingTurnedOff":  [

                                                 ],
    "enterpriseCloudPrintDiscoveryEndPoint":  null,
    "enterpriseCloudPrintOAuthAuthority":  null,
    "enterpriseCloudPrintOAuthClientIdentifier":  null,
    "enterpriseCloudPrintResourceIdentifier":  null,
    "enterpriseCloudPrintDiscoveryMaxLimit":  null,
    "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier":  null,
    "messagingBlockSync":  false,
    "messagingBlockMMS":  false,
    "messagingBlockRichCommunicationServices":  false,
    "printerNames":  [

                     ],
    "printerDefaultName":  null,
    "printerBlockAddition":  false,
    "searchBlockDiacritics":  true,
    "searchDisableAutoLanguageDetection":  true,
    "searchDisableIndexingEncryptedItems":  true,
    "searchEnableRemoteQueries":  false,
    "searchDisableUseLocation":  true,
    "searchDisableLocation":  true,
    "searchDisableIndexerBackoff":  true,
    "searchDisableIndexingRemovableDrive":  true,
    "searchEnableAutomaticIndexSizeManangement":  false,
    "searchBlockWebResults":  true,
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "none",
    "oneDriveDisableFileSync":  true,
    "systemTelemetryProxyServer":  null,
    "inkWorkspaceAccess":  "notConfigured",
    "inkWorkspaceAccessState":  "notConfigured",
    "inkWorkspaceBlockSuggestedApps":  true,
    "smartScreenEnableAppInstallControl":  true,
    "personalizationDesktopImageUrl":  null,
    "personalizationLockScreenImageUrl":  null,
    "bluetoothAllowedServices":  [

                                 ],
    "bluetoothBlockAdvertising":  true,
    "bluetoothBlockDiscoverableMode":  true,
    "bluetoothBlockPrePairing":  true,
    "edgeBlockAutofill":  true,
    "edgeBlocked":  true,
    "edgeCookiePolicy":  "userDefined",
    "edgeBlockDeveloperTools":  true,
    "edgeBlockSendingDoNotTrackHeader":  false,
    "edgeBlockExtensions":  true,
    "edgeBlockInPrivateBrowsing":  false,
    "edgeBlockJavaScript":  true,
    "edgeBlockPasswordManager":  true,
    "edgeBlockAddressBarDropdown":  false,
    "edgeBlockCompatibilityList":  true,
    "edgeClearBrowsingDataOnExit":  true,
    "edgeAllowStartPagesModification":  false,
    "edgeDisableFirstRunPage":  true,
    "edgeBlockLiveTileDataCollection":  true,
    "edgeSyncFavoritesWithInternetExplorer":  true,
    "edgeFavoritesListLocation":  null,
    "edgeBlockEditFavorites":  true,
    "cellularBlockDataWhenRoaming":  true,
    "cellularBlockVpn":  false,
    "cellularBlockVpnWhenRoaming":  true,
    "cellularData":  "allowed",
    "defenderBlockEndUserAccess":  true,
    "defenderDaysBeforeDeletingQuarantinedMalware":  2,
    "defenderDetectedMalwareActions":  null,
    "defenderSystemScanSchedule":  "userDefined",
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderScanMaxCpu":  null,
    "defenderMonitorFileActivity":  "userDefined",
    "defenderPotentiallyUnwantedAppAction":  "deviceDefault",
    "defenderPotentiallyUnwantedAppActionSetting":  "userDefined",
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPromptForSampleSubmission":  "userDefined",
    "defenderRequireBehaviorMonitoring":  true,
    "defenderRequireCloudProtection":  false,
    "defenderRequireNetworkInspectionSystem":  false,
    "defenderRequireRealTimeMonitoring":  true,
    "defenderScanArchiveFiles":  false,
    "defenderScanDownloads":  true,
    "defenderScanNetworkFiles":  true,
    "defenderScanIncomingMail":  true,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanRemovableDrivesDuringFullScan":  true,
    "defenderScanScriptsLoadedInInternetExplorer":  true,
    "defenderSignatureUpdateIntervalInHours":  null,
    "defenderScanType":  "userDefined",
    "defenderScheduledScanTime":  null,

    "defenderScheduledQuickScanTime":  "23:00:00",
    
    "defenderCloudBlockLevel":  "notConfigured",
    "defenderCloudExtendedTimeout":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderBlockOnAccessProtection":  false,
    "defenderScheduleScanDay":  "everyday",
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  true,
    "lockScreenBlockToastNotifications":  true,
    "lockScreenTimeoutInSeconds":  null,
    "passwordBlockSimple":  true,

    "passwordExpirationDays":  24,
    "passwordMinimumLength":  15,

    "passwordMinutesOfInactivityBeforeScreenTimeout":  null,
    "passwordMinimumCharacterSetCount":  null,

    "passwordPreviousPasswordBlockCount":  21,
    
    "passwordRequired":  true,
    "passwordRequireWhenResumeFromIdleState":  true,
    "passwordRequiredType":  "deviceDefault",
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "privacyAdvertisingId":  "notConfigured",
    "privacyAutoAcceptPairingAndConsentPrompts":  false,
    "privacyBlockInputPersonalization":  false,
    "privacyBlockPublishUserActivities":  false,
    "privacyBlockActivityFeed":  false,
    "startBlockUnpinningAppsFromTaskbar":  false,
    "startMenuAppListVisibility":  "userDefined",
    "startMenuHideChangeAccountSettings":  false,
    "startMenuHideFrequentlyUsedApps":  false,
    "startMenuHideHibernate":  false,
    "startMenuHideLock":  false,
    "startMenuHidePowerButton":  false,
    "startMenuHideRecentJumpLists":  false,
    "startMenuHideRecentlyAddedApps":  false,
    "startMenuHideRestartOptions":  false,
    "startMenuHideShutDown":  false,
    "startMenuHideSignOut":  false,
    "startMenuHideSleep":  true,
    "startMenuHideSwitchAccount":  true,
    "startMenuHideUserTile":  false,
    "startMenuLayoutEdgeAssetsXml":  null,
    "startMenuLayoutXml":  null,
    "startMenuMode":  "userDefined",
    "startMenuPinnedFolderDocuments":  "notConfigured",
    "startMenuPinnedFolderDownloads":  "notConfigured",
    "startMenuPinnedFolderFileExplorer":  "notConfigured",
    "startMenuPinnedFolderHomeGroup":  "notConfigured",
    "startMenuPinnedFolderMusic":  "notConfigured",
    "startMenuPinnedFolderNetwork":  "notConfigured",
    "startMenuPinnedFolderPersonalFolder":  "notConfigured",
    "startMenuPinnedFolderPictures":  "notConfigured",
    "startMenuPinnedFolderSettings":  "notConfigured",
    "startMenuPinnedFolderVideos":  "notConfigured",
    "settingsBlockSettingsApp":  true,
    "settingsBlockSystemPage":  true,
    "settingsBlockDevicesPage":  true,
    "settingsBlockNetworkInternetPage":  false,
    "settingsBlockPersonalizationPage":  true,
    "settingsBlockAccountsPage":  true,
    "settingsBlockTimeLanguagePage":  false,
    "settingsBlockEaseOfAccessPage":  false,
    "settingsBlockPrivacyPage":  true,
    "settingsBlockUpdateSecurityPage":  true,
    "settingsBlockAppsPage":  true,
    "settingsBlockGamingPage":  true,
    "windowsSpotlightBlockConsumerSpecificFeatures":  true,
    "windowsSpotlightBlocked":  false,
    "windowsSpotlightBlockOnActionCenter":  false,
    "windowsSpotlightBlockTailoredExperiences":  false,
    "windowsSpotlightBlockThirdPartyNotifications":  true,
    "windowsSpotlightBlockWelcomeExperience":  false,
    "windowsSpotlightBlockWindowsTips":  true,
    "windowsSpotlightConfigureOnLockScreen":  "notConfigured",
    "networkProxyApplySettingsDeviceWide":  false,
    "networkProxyDisableAutoDetect":  false,
    "networkProxyAutomaticConfigurationUrl":  null,
    "networkProxyServer":  null,
    "accountsBlockAddingNonMicrosoftAccountEmail":  true,
    "antiTheftModeBlocked":  false,
    "bluetoothBlocked":  true,
    "cameraBlocked":  true,
    "connectedDevicesServiceBlocked":  false,
    "certificatesBlockManualRootCertificateInstallation":  true,
    "copyPasteBlocked":  false,
    "cortanaBlocked":  true,
    "deviceManagementBlockFactoryResetOnMobile":  false,
    "deviceManagementBlockManualUnenroll":  true,
    
    "safeSearchFilter":  "strict",

    "edgeBlockPopups":  true,
    "edgeBlockSearchSuggestions":  true,
    "edgeBlockSendingIntranetTrafficToInternetExplorer":  false,
    "edgeRequireSmartScreen":  true,
    "edgeEnterpriseModeSiteListLocation":  null,
    "edgeFirstRunUrl":  null,
    "edgeSearchEngine":  null,
    "edgeHomepageUrls":  [

                         ],
    "edgeBlockAccessToAboutFlags":  false,
    "smartScreenBlockPromptOverride":  true,
    "smartScreenBlockPromptOverrideForFiles":  true,
    "webRtcBlockLocalhostIpAddress":  false,
    "internetSharingBlocked":  false,
    "settingsBlockAddProvisioningPackage":  true,
    "settingsBlockRemoveProvisioningPackage":  true,
    "settingsBlockChangeSystemTime":  false,
    "settingsBlockEditDeviceName":  true,
    "settingsBlockChangeRegion":  false,
    "settingsBlockChangeLanguage":  false,
    "settingsBlockChangePowerSleep":  true,
    "locationServicesBlocked":  true,
    "microsoftAccountBlocked":  true,
    "microsoftAccountBlockSettingsSync":  false,
    "nfcBlocked":  true,
    "resetProtectionModeBlocked":  false,
    "screenCaptureBlocked":  false,
    "storageBlockRemovableStorage":  false,
    "storageRequireMobileDeviceEncryption":  false,
    "usbBlocked":  false,
    "voiceRecordingBlocked":  true,
    "wiFiBlockAutomaticConnectHotspots":  true,
    "wiFiBlocked":  false,
    "wiFiBlockManualConfiguration":  false,
    "wiFiScanInterval":  null,
    "wirelessDisplayBlockProjectionToThisDevice":  false,
    "wirelessDisplayBlockUserInputFromReceiver":  false,
    "wirelessDisplayRequirePinForPairing":  false,
    "windowsStoreBlocked":  true,
    "appsAllowTrustedAppsSideloading":  "allowed",
    "windowsStoreBlockAutoUpdate":  false,
    "developerUnlockSetting":  "blocked",
    "sharedUserAppDataAllowed":  false,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  true,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  true,
    "gameDvrBlocked":  true,
    "experienceBlockDeviceDiscovery":  true,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  false,
    "appManagementMSIAllowUserControlOverInstall":  false,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  false
}
"@

####################################################
$System2 = @"

{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "id":  "4b2b4425-0377-4311-92a2-2cecc89ccda0",
    "createdDateTime":  "2019-03-01T11:22:14.7951636Z",
    "description":  "System Hardening configuration for Secure Workstation -  this configuration is custom OMA-URI",
    "displayName":  "System Hardening configuration for Secure Workstation - Custom",
    "version":  1,
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Error Reporting - Disable Windows Error Reporting",
                            "description":  "Error Reporting - Disable Windows Error Reporting",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/ErrorReporting/DisableWindowsErrorReporting",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Data Protection - Allow Direct Memory Access",
                            "description":  "Data Protection - Allow Direct Memory Access",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/DataProtection/AllowDirectMemoryAccess",
                            "value":  0
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Windows Logon - Don\u0027t Display Network Selection UI",
                            "description":  "Windows Logon - Don\u0027t Display Network Selection UI",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DontDisplayNetworkSelectionUI",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power - Allow Standby When Sleeping Plugged In",
                            "description":  "Power - Allow Standby When Sleeping Plugged In",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/AllowStandbyWhenSleepingPluggedIn",
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power - Require Password When Computer Wakes On Battery",
                            "description":  "Power - Require Password When Computer Wakes On Battery",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power - Require Password When Computer Wakes Plugged In",
                            "description":  "Power - Require Password When Computer Wakes Plugged In",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesPluggedIn",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Remote Assistance - Solicited Remote Assistance",
                            "description":  "Remote Assistance - Solicited Remote Assistance",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance",
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "AutoPlay - Disallow Autoplay For Non Volume Devices",
                            "description":  "AutoPlay - Disallow Autoplay For Non Volume Devices",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/AutoPlay/DisallowAutoplayForNonVolumeDevices",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Remote Desktop Services - Do Not Allow Drive Redirection",
                            "description":  "Remote Desktop Services - Do Not Allow Drive Redirection",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowDriveRedirection",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Remote Desktop Services - Prompt For Password Upon Connection",
                            "description":  "Remote Desktop Services - Prompt For Password Upon Connection",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/PromptForPasswordUponConnection",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Remote Desktop Services - Require Secure RPC Communication",
                            "description":  "Remote Desktop Services - Require Secure RPC Communication",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/RequireSecureRPCCommunication",
                            "value":  "\u003cenabled/\u003e"
                        },

                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Device Lock - Prevent Lock Screen Slide Show",
                            "description":  "Device Lock - Prevent Lock Screen Slide Show",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Autoplay - Set Default Auto Run Behavior",
                            "description":  "Autoplay - Set Default Auto Run Behavior",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior",
                            "value":  "\u003cenabled/\u003e\n\u003cdata id=\"NoAutorun_Dropdown\" value=\"1\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Autoplay - Turn Off Auto Play",
                            "description":  "Autoplay - Turn Off Auto Play",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay",
                            "value":  "\u003cenabled/\u003e\n\u003cdata id=\"Autorun_Box\" value=\"255\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "System - Boot Start Driver Initialization",
                            "description":  "System - Boot Start Driver Initialization (Good, Unknown and bad but critical)",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/System/BootStartDriverInitialization",
                            "value":  "\u003cenabled/\u003e\n\u003cdata id=\"SelectDriverLoadPolicy\" value=\"3\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RPC - Restrict Unauthenticated RPC Clients",
                            "description":  "RPC - Restrict Unauthenticated RPC Clients",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RestrictUnauthenticatedRPCClients",
                            "value":  "\u003cenabled/\u003e\n\u003cdata id=\"RpcRestrictRemoteClientsList\" value=\"1\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Remote Desktop Services - Client Connection Encryption Level",
                            "description":  "Remote Desktop Services - Client Connection Encryption Level",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/ClientConnectionEncryptionLevel",
                            "value":  "\u003cenabled/\u003e\n\u003cdata id=\"TS_ENCRYPTION_LEVEL\" value=\"3\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Network Isolation - Enterprise Proxy Servers Are Authoritative ",
                            "description":  "Network Isolation - Enterprise Proxy Servers Are Authoritative ",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/NetworkIsolation/EnterpriseProxyServersAreAuthoritative",
                            "value":  1
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MS Security Guide - Configure SMBV1 Client Driver",
                            "description":  "MS Security Guide - Configure SMBV1 Client Driver",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver",
                            "value":  "\u003cenabled/\u003e \n\u003cdata id=\"Pol_SecGuide_SMB1ClientDriver\" value=\"4\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Windows PowerShell - Turn On Power Shell Script Block Logging",
                            "description":  "Windows PowerShell - Turn On Power Shell Script Block Logging",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/WindowsPowerShell/TurnOnPowerShellScriptBlockLogging",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Device Lock - Prevent Enabling Lock Screen Camera",
                            "description":  "Device Lock - Prevent Enabling Lock Screen Camera",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MS Security Guide - Apply UAC Restrictions To Local Accounts On Network Logon",
                            "description":  "MS Security Guide - Apply UAC Restrictions To Local Accounts On Network Logon",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MS Security Guide - Configure SMBV1 Server",
                            "description":  "MS Security Guide - Configure SMBV1 Server",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1Server",
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MS Security Guide - Enable Structured Exception Handling Overwrite Protection",
                            "description":  "MS Security Guide - Enable Structured Exception Handling Overwrite Protection",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection",
                            "value":  "\u003cenabled/\u003e"
                        },
                       
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MS Security Guide - WDigest Authentication",
                            "description":  "MS Security Guide - WDigest Authentication",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/WDigestAuthentication",
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Lanman Workstation - Enable Insecure Guest Logons",
                            "description":  "Lanman Workstation - Enable Insecure Guest Logons",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/LanmanWorkstation/EnableInsecureGuestLogons",
                            "value":  0
                        },

                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "MDM Wins Over GP",
                            "description":  "MDM Wins Over GP",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/ControlPolicyConflict/MDMWinsOverGP",
                            "value":  1
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System Services - Configure Home Group Listener Service Startup Mode",
                            "description":  "System Services - Configure Home Group Listener Service Startup Mode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureHomeGroupListenerServiceStartupMode",
                            "value":  4
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System Services - Configure Home Group Provider Service Startup Mode",
                            "description":  "System Services - Configure Home Group Provider Service Startup Mode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureHomeGroupProviderServiceStartupMode",
                            "value":  4
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System Services - Configure Xbox Accessory Management Service Startup Mode",
                            "description":  "System Services - Configure Xbox Accessory Management Service Startup Mode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureXboxAccessoryManagementServiceStartupMode",
                            "value":  4
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System Services - Configure Xbox Live Auth Manager Service Startup Mode",
                            "description":  "System Services - Configure Xbox Live Auth Manager Service Startup Mode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureXboxLiveAuthManagerServiceStartupMode",
                            "value":  4
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System Services - Configure Xbox Live Game Save Service Startup Mode",
                            "description":  "System Services - Configure Xbox Live Game Save Service Startup Mode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureXboxLiveGameSaveServiceStartupMode",
                            "value":  4
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System Services - Configure Xbox Live Networking Service Startup Mode",
                            "description":  "System Services - Configure Xbox Live Networking Service Startup Mode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureXboxLiveNetworkingServiceStartupMode",
                            "value":  4
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSS Legacy - Allow ICMP Redirects To Override OSPF Generated Routes",
                            "description":  "MSS Legacy - Allow ICMP Redirects To Override OSPF Generated Routes",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSLegacy - Allow The Computer To Ignore Net BIOS Name Release Requests Except From WINS Servers",
                            "description":  "MSSLegacy - Allow The Computer To Ignore Net BIOS Name Release Requests Except From WINS Servers",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSS Legacy - IP Source Routing Protection Level",
                            "description":  "MSS Legacy - IP Source Routing Protection Level",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
                            "value":  "\u003cenabled/\u003e \n\u003cdata id=\"DisableIPSourceRouting\" value=\"2\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSS Legacy - IPv6 Source Routing Protection Level",
                            "description":  "MSS Legacy - IPv6 Source Routing Protection Level",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel",
                            "value":  "\u003cenabled/\u003e \n\u003cdata id=\"DisableIPSourceRoutingIPv6\" value=\"2\"/\u003e"
                        }
                    ]
}
"@

####################################################
$User = @"

{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "id":  "e044b010-6ecb-45d6-b846-d2d7215053b7",
    "createdDateTime":  "2019-03-01T11:22:49.2016579Z",
    "description":  "User account hardening for Secure Workstation - custom OMA-URI configurations",
    "displayName":  "User account hardening for Secure Workstation - Custom",
    "version":  1,
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Credentials UI - Disable Password Reveal",
                            "description":  "Credentials UI - Disable Password Reveal",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal",
                            "value":  "\u003cenabled/\u003e"
                        }
                    ]
}

"@
####################################################

####################################################
$Baseline = @"

{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Secured workstation Compliance baseline Windows10 (1803)",
    "displayName":  "Secured workstation Compliance baseline Windows10 (1803)",
    "passwordRequired":  true,
    "passwordBlockSimple":  true,
    "passwordRequiredToUnlockFromIdle":  true,
    "passwordMinutesOfInactivityBeforeLock":  15,
    "passwordExpirationDays":  60,
    "passwordMinimumLength":  16,
    "passwordMinimumCharacterSetCount":  3,
    "passwordRequiredType":  "alphanumeric",
    "passwordPreviousPasswordBlockCount":  7,
    "requireHealthyDeviceReport":  true,
    "osMinimumVersion":  "10.0.17763",
    "osMaximumVersion":  null,
    "mobileOsMinimumVersion":  null,
    "mobileOsMaximumVersion":  null,
    "earlyLaunchAntiMalwareDriverEnabled":  false,
    "bitLockerEnabled":  true,
    "secureBootEnabled":  true,
    "codeIntegrityEnabled":  true,
    "storageRequireEncryption":  true,
    "activeFirewallRequired":  true,
    "defenderEnabled":  true,
    "defenderVersion":  null,
    "signatureOutOfDate":  true,
    "rtpEnabled":  true,
    "antivirusRequired":  true,
    "antiSpywareRequired":  true,
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "High",
    "configurationManagerComplianceRequired":  false,
    "validOperatingSystemBuildRanges":  [

                                        ],
"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]
}


"@
####################################################

Add-DeviceConfigurationPolicy -Json $Applocker # OK
Add-DeviceConfigurationPolicy -Json $Firewall # OK
Add-DeviceConfigurationPolicy -Json $System1 # OK
Add-DeviceConfigurationPolicy -Json $System2 # OK
Add-DeviceConfigurationPolicy -Json $User # OK
Add-DeviceCompliancePolicybaseline -Json $Baseline #OK



