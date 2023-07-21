
# Enterprise Profile configuration

The scripts for configuring the Enterprise security baseline are located in this folder. 
Before the scripts can be run install Azure AD powershell module on your device

```powershell
Import-Module Microsoft.Graph -force
```
and allow scripts to run on your device;
```powershell
Set-ExecutionPolicy remotesigned
```

[**MasterScript_ENT.PS1**](MasterScript-ENT.ps1) - This script is used to import the Compliance policies, Configuration profiles used to apply the Enterprise Profile settings
   
   To import the Enterprise Profile configuration settings into your tenant
   Open powershell comsole
   Navigate to ENT folder in Repo 
   ```powershell
   .\MasterScript-ENT.ps1
   ```
    
Enter **username** and **password** of an account that has Intune Administrator (preferred) or Global Admin privilege

Wait for the import process to complete.

The MasterScript_ENT.ps1 file calls the following scripts to import the Compliance Policies, Configuration Profiles



[**Import-ENT-DeviceCompliancePolicies.ps1**](Import-ENT-DeviceCompliancePolicies.ps1) - This scripts imports the three device compliance policies for the Enterprise profile. Three policies are used to ensure that Conditional Access does not prevent a user from being able to access resources. Refer to [Windows 10 and later settings to mark devices as compliant or not compliant using Intune](https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows)
   
   1. [Enterprise Compliance ATP](JSON/DeviceCompliance/ENT-Compliance-ATP.json) policy is used to feed the Threat Intelligence data from Microsoft Defender for Endpoint into the devices compliance state so its signals can be used as part of the Conditional Access evaluation process.

   2. [Enterprise Compliance Delayed](JSON/DeviceCompliance/ENT-Compliance-Delayed.json) policy applies a more complete set of compliance settings to the device but its application is delayed by 24 hours.  this is because the device health attestation that is required to assess policies like BitLocker and Secure Boot is only calculated once a device has rebooted and then might take a number of hours to process whether the device is compliant or not.

   3. [ENT-Compliance-Immediate](JSON/DeviceCompliance/ENT-Compliance-Immediate.json) policy is used to apply a minimum level of compliance to users and is configured to apply immediately.

[**Import-ENT-DeviceConfiguration.ps1**](Import-ENT-DeviceConfiguration.ps1) - this script is used to import the Device Configuration profiles that harden the Operating System. there are five profiles used:
1.  [Enterprise-Config-Win10-Custom-CSP](JSON/DeviceConfiguration/Enterprise-Config-Win10-Custom-CSP_17-11-2020-17-00-43.json) Applies configuration service provider (CSP) settings that are not available in the Endpoint Manager UI, refer to [Configuration service provider reference](https://docs.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-reference) for the complete list of the CSP settings available.
2.  [Enterprise-Config-Win10-Device-Restrictions-UI](JSON/DeviceConfiguration/Enterprise-Config-Win10-Device-Restrictions-UI_17-11-2020-17-00-43.json) applies settings that restrict cloud account use, configure password policy, Microsoft Defender SmartScreen, Microsoft Defender Antivirus.  Refer to [Windows 10 (and newer) device settings to allow or restrict features using Intune](https://docs.microsoft.com/en-us/mem/intune/configuration/device-restrictions-windows-10) for more details of the settings applied using the profile.
3.  [Enterprise-Config-Win10-Endpoint-Protection-UI](JSON/DeviceConfiguration/Enterprise-Config-Win10-Endpoint-Protection-UI_17-11-2020-17-00-43.json) applies settings that are used to protect devices in endpoint protection configuration profiles including BitLocker, Device Guard, Microsoft Defender Firewall, Microsoft Defender Exploit Guard, refer to [Windows 10 (and later) settings to protect devices using Intune](https://docs.microsoft.com/en-us/mem/intune/protect/endpoint-protection-windows-10?toc=/intune/configuration/toc.json&bc=/intune/configuration/breadcrumb/toc.json) for more details of the settings applied using the profile.
4.  [Enterprise-Config-Win10-Identity-Protection-UI](JSON/DeviceConfiguration/Enterprise-Config-Win10-Identity-Protection-UI_17-11-2020-17-00-43.json) applies the Windows Hello for Business settings to devices, refer to [Windows 10 device settings to enable Windows Hello for Business in Intune](https://docs.microsoft.com/en-us/mem/intune/protect/identity-protection-windows-settings?toc=/intune/configuration/toc.json&bc=/intune/configuration/breadcrumb/toc.json) for more details of the settings applied using the profile.

[**Import-ENT-DeviceConfigurationADMX.ps1**](JSON/DeviceConfigurationADMX/Enterprise-Edge%20Version%2085%20-%20Computer.json) this script is used to import the Device Configuration ADMX Template profile that configures Microsoft Edge security settings.

1.  [Enterprise-Edge Version 85 - Computer](JSON/DeviceConfigurationADMX/Enterprise-Edge%20Version%2085%20-%20Computer.json) applies administrative policies that control features in Microsoft Edge version 77 and later, refer to [Microsoft Edge - Policies](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies) or more details of the settings applied using the profile.
