<##################################################################################################
#
.SYNOPSIS
This script downloads, and installs the MMA agent (64 bit AMD processor). 
The MMA agent provide the required monitoring of a device APPLOCKER instance. 
This deployment is sample code to be used with the guidance at aka.ms/securedworkstation, using the Secure workstation profile.

The Secure workstation profile once loaded in Intune will enable all targeted devices to beging auditing all
DLL, EXE, MSI, and Store Apps of APPLOCKER events.


NOTE - this enables ALL informational applocker monitoring of DLL, EXE, MSI, and Store Apps. This WILL
generate large traffic to your Azure instance of your Log Analytics workspace. USE with caution.


.NOTES
    FileName:    InstallMMAforApplocker.ps1
    Author:      Microsoft
	Revised:     Frank Simorjay
    Created:     05-09-2019
	Revised:     05-09-2019
    Version:     1.0 
    
#>
###################################################################################################
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

# Set the parameters for your installation. Note this sample targets the generic AMD64 bit MMA client. 
$FileName = "MMASetup-AMD64.exe"
$MMAFolder = 'C:\Source' #sample downloads the bits to this folder
$MMALogsFolder = 'C:\MMAInstallLogs' #instal the bits and start logging activity of the installation effort - good for debugging
$MMAFile = $MMAFolder + "\" + $FileName
$MMALogsFile = $MMALogsFolder + "\MMAAgentInstallLog.txt"
$WorkSpaceID = "88dad409-515e-4409-b2b5-e3667a0e5c6b"
$WorkSpaceKey = "YOUR KEY GOES HERE" #lookup your log analytics WORK SPACE key and paste to this line.
$MMAInstalled = $false

if (-not (Test-Path $MMALogsFolder)){
	New-Item $MMALogsFolder -type Directory | Out-Null
}

# Start logging the actions
Start-Transcript -Path $MMALogsFile -Append

# Configure AppIdSvc for Automatic start
SC.EXE config AppIdSvc start= auto
Write-Host "Configured AppIdSvc to auto start."

try 
{
	# Check to see if MMA is already installed.
	# This could happen if the customer already uses MMA or if we deployed this previously
    $mma = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
	$MMAInstalled = $true
	Write-Host "MMA has already been installed. Configuring MMA for MMD."
	# Running this with a previously configured workspace makes this a no op
	$mma.AddCloudWorkspace($WorkSpaceID, $WorkSpaceKey)
	Exit 0
}
catch 
{
	if ($MMAInstalled)
	{
		# An error occurred while trying to configure the workspace
		Write-Warning $_
		Exit 1
	}
	Write-Host "MMA has not been installed yet"
}


# Check if folder exists, if not, create it
 if (Test-Path $MMAFolder){
 Write-Host "The folder $MMAFolder already exists."
 } 
 else 
 {
 Write-Host "The folder $MMAFolder does not exist, creating..." -NoNewline
 New-Item $MMAFolder -type Directory | Out-Null
 Write-Host "done!" -ForegroundColor Green
 }

# Change the location to the specified folder
Set-Location $MMAFolder

# Check if file exists, if not, download it
 if (Test-Path $FileName){
 Write-Host "The file $FileName already exists."
 }
 else
 {
 Write-Host "The file $FileName does not exist, downloading..." -NoNewline
 $URL = "https://go.microsoft.com/fwlink/?LinkId=828603"
 Invoke-WebRequest -Uri $URl -OutFile $MMAFile | Out-Null
 Write-Host "done!" -ForegroundColor Green
 }
 
# Install the agent
Write-Host "Installing Microsoft Monitoring Agent.." -nonewline
$ArgumentList = '/C:"setup.exe /qn ADD_OPINSIGHTS_WORKSPACE=1 '+  "OPINSIGHTS_WORKSPACE_ID=$WorkspaceID " + "OPINSIGHTS_WORKSPACE_KEY=$WorkSpaceKey " +'AcceptEndUserLicenseAgreement=1"'
Start-Process $FileName -ArgumentList $ArgumentList -ErrorAction Stop -Wait | Out-Null
Write-Host "done!" -ForegroundColor Green

# Change the location to C: to remove the created folder
Set-Location -Path "C:\"

# Remove the folder with the agent
 if (-not (Test-Path $MMAFolder)) {
 Write-Host "The folder $MMAFolder does not exist."
 } 
 else 
 {
 Write-Host "Removing the folder $MMAFolder ..." -NoNewline
 Remove-Item $MMAFolder -Force -Recurse | Out-Null
 Write-Host "done!" -ForegroundColor Green
 }

Stop-Transcript