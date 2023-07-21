# Specialized Profile configuration

The scripts for configuring the Specialized security baseline are located in this folder. 
Before the scripts can be run install Azure AD powershell module on your device

```powershell
Import-Module Microsoft.Graph -force
```
and allow scripts to run on your device;
```powershell
Set-ExecutionPolicy remotesigned
```

[**MasterScript_SPE.PS1**](MasterScript-SPE.ps1) - This script is used to import the Compliance policies, Configuration profiles used to apply the Specialized Profile settings
   
   To import the Specialized Profile configuration settings into your tenant
   Open powershell console
   Navigate to SPE folder in Repo 
   ```powershell
   .\MasterScript-SPE.ps1
   ```
    
Enter **username** and **password** of an account that has Intune Administrator (preferred) or Global Admin privilege

Wait for the import process to complete.

The MasterScript_SPE.ps1 file calls the following scripts to import the Compliance Policies, Configuration Profiles



[**Import-SPE-DeviceCompliancePolicies.ps1**](Import-SPE-DeviceCompliancePolicies.ps1) - This scripts imports the three device compliance policies for the Specialized profile. Three policies are used to ensure that Conditional Access does not prevent a user from being able to access resources. Refer to [Windows 10 and later settings to mark devices as compliant or not compliant using Intune](https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows)
   
   1. [Specialized Compliance ATP](JSON/DeviceCompliance/SPE-Compliance-ATP.json) policy is used to feed the Threat Intelligence data from Microsoft Defender for Endpoint into the devices compliance state so its signals can be used as part of the Conditional Access evaluation process.

   2. [Specialized Compliance Delayed](JSON/DeviceCompliance/SPE-Compliance-Delayed.json) policy applies a more complete set of compliance settings to the device but its application is delayed by 24 hours.  this is because the device health attestation that is required to assess policies like BitLocker and Secure Boot is only calculated once a device has rebooted and then might take a number of hours to process whether the device is compliant or not.

   3. [Specialized-Compliance-Immediate](JSON/DeviceCompliance/SPE-Compliance-Immediate.json) policy is used to apply a minimum level of compliance to users and is configured to apply immediately.

[**Import-SPE-DeviceConfiguration.ps1**](Import-SPE-DeviceConfiguration.ps1) - this script is used to import the Device Configuration profiles that harden the Operating System. there are five profiles used:
1.  [Specialized-Config-Win10-Custom-CSP](JSON/DeviceConfiguration/Specialized-Config-Win10-Custom-CSP_17-11-2020-17-00-43.json) Applies configuration service provider (CSP) settings that are not available in the Endpoint Manager UI, refer to [Configuration service provider reference](https://docs.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-reference) for the complete list of the CSP settings available.
2.  [Specialized-Config-Win10-Device-Restrictions-UI](JSON/DeviceConfiguration/Specialized-Config-Win10-Device-Restrictions-UI_17-11-2020-17-00-43.json) applies settings that restrict cloud account use, configure password policy, Microsoft Defender SmartScreen, Microsoft Defender Antivirus.  Refer to [Windows 10 (and newer) device settings to allow or restrict features using Intune](https://docs.microsoft.com/en-us/mem/intune/configuration/device-restrictions-windows-10) for more details of the settings applied using the profile.
3.  [Specialized-Config-Win10-Endpoint-Protection-UI](JSON/DeviceConfiguration/Specialized-Config-Win10-Endpoint-Protection-UI_17-11-2020-17-00-43.json) applies settings that are used to protect devices in endpoint protection configuration profiles including BitLocker, Device Guard, Microsoft Defender Firewall, Microsoft Defender Exploit Guard, refer to [Windows 10 (and later) settings to protect devices using Intune](https://docs.microsoft.com/en-us/mem/intune/protect/endpoint-protection-windows-10?toc=/intune/configuration/toc.json&bc=/intune/configuration/breadcrumb/toc.json) for more details of the settings applied using the profile.
4.  [Specialized-Config-Win10-Identity-Protection-UI](JSON/DeviceConfiguration/Specialized-Config-Win10-Identity-Protection-UI_17-11-2020-17-00-43.json) applies the Windows Hello for Business settings to devices, refer to [Windows 10 device settings to enable Windows Hello for Business in Intune](https://docs.microsoft.com/en-us/mem/intune/protect/identity-protection-windows-settings?toc=/intune/configuration/toc.json&bc=/intune/configuration/breadcrumb/toc.json) for more details of the settings applied using the profile.

5.  [SPE-Win10-AppLocker-Custom-CSP](JSON/DeviceConfiguration/SPE-Win10-AppLocker-Custom-CSP_25-11-2020-17-42-11.json) applies the Restricted Execution Model policies in audit mode. The AppLocker configuration is configured to allow applications to run under C:\Program Files, C:\Program Files (x86) and C:\Windows, with user writable paths under blocked. the characteristics for the AppLocker approach is:
    *  Assumption is that users are non-privileged users.
    *  Wherever a user can write they are blocked from executing
    *  Wherever a user can execute they are blocked from writing

The Specialized policy also includes rules to allow OneDrive and Microsoft Teams clients to run under the user's profile directory

[**Import-SPE-DeviceConfigurationADMX.ps1**](JSON/DeviceConfigurationADMX/Specialized-Edge%20Version%2085%20-%20Computer.json) this script is used to import the Device Configuration ADMX Template profile that configures Microsoft Edge security settings.

1. [Specialized-Edge Version 85 - Computer](JSON/DeviceConfigurationADMX/Specialized-Edge%20Version%2085%20-%20Computer.json) applies administrative policies that control features in Microsoft Edge version 77 and later, refer to [Microsoft Edge - Policies](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies) or more details of the settings applied using the profile.

