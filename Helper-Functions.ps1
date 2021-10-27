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
    param    (
        [Parameter(Mandatory = $true)]
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
    
    if ($AadModule.count -gt 1) {
        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
        # Checking if there are multiple versions of the same module found
        if ($AadModule.count -gt 1) {
            $aadModule = $AadModule | Select-Object -Unique
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
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
        # If the accesstoken is valid then create the authentication header
        if ($authResult.AccessToken) {
            # Creating header for Authorization token
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
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

Function Create-IntuneScopeTag {
    <#
    .SYNOPSIS
    This function is used to create a scope tag in intune using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and creates a scope tag
    .EXAMPLE
    Create-IntuneScopeTag -Name PrivIdentity-tag
    Creates a scope tag
    .NOTES
    NAME: Create-IntuneScopeTag
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $graphApiVersion = "Beta"
    $DCP_resource = "/deviceManagement/roleScopeTags"
    Write-Verbose "Resource: $DCP_resource"

    try {        
        $Body = @{
            "@odata.type"= "#microsoft.graph.roleScopeTag"
            displayName = $Name
            description = "Tag for privileged identities"
            isBuiltIn = $false
        } | ConvertTo-Json
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $Body -ContentType "application/json"        
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
    [cmdletbinding()]
    param(
        $JSON
    )

    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    Write-Verbose "Resource: $DCP_resource"

    try {
        if ($JSON -eq "" -or $JSON -eq $null) {
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
    [cmdletbinding()]
    param(
        $ConfigurationPolicyId,
        $TargetGroupId,
        $Assignment
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assignments"
    
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
        $ConfPolAssign = "$ConfigurationPolicyId" + "_" + "$TargetGroupId"
        $JSON = @"
        {
    "target": {
    "@odata.type": "#microsoft.graph.$Assignment",
    "groupId": "$TargetGroupId"
                }
        }
"@
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
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
    [cmdletbinding()]
    param(
        $name
    )
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    try {
        if ($Name) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
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
    param(
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
                $AllUsers {
                    $grp = [PSCustomObject]@{ displayName = "All users" }; $grp           
                }
                $AllDevices {
                    $grp = [PSCustomObject]@{ displayName = "All devices" }; $grp         
                }
                default {
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value  
                }
            }                
        }
        elseif ($GroupName -eq "" -or $GroupName -eq $null) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        }
        else {
            if (!$Members) {
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            }
            elseif ($Members) {
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
                if ($Group) {
                    $GID = $Group.id
                    $Group.displayName
                    write-host
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
                }
            }
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