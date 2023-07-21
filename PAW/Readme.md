# Privileged Profile configuration

The scripts for configuring the Privileged security baseline are located in this folder. 
Before the scripts can be run install Azure AD powershell module on your device

```powershell
Import-Module Microsoft.Graph -force
```
and allow scripts to run on your device;
```powershell
Set-ExecutionPolicy remotesigned
```

[**MasterScript_PAW.PS1**](MasterScript-PAW.ps1) - This script is used to import the Compliance policies, Configuration profiles used to apply the Privileged Profile settings
   
   To import the Privileged Profile configuration settings into your tenant
   Open powershell console
   Navigate to PAW folder in Repo 
   ```powershell
   .\MasterScript-PAW.ps1
   ```
    
PAWer **username** and **password** of an account that has Intune Administrator (preferred) or Global Admin privilege

Wait for the import process to complete.

The MasterScript_PAW.ps1 file calls the following scripts to import the Compliance Policies, Configuration Profiles



[**Import-PAW-DeviceCompliancePolicies.ps1**](Import-PAW-DeviceCompliancePolicies.ps1) - This scripts imports the three device compliance policies for the Privileged profile. Three policies are used to ensure that Conditional Access does not prevent a user from being able to access resources. Refer to [Windows 10 and later settings to mark devices as compliant or not compliant using Intune](https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows)
   
   1. [Privileged Compliance ATP](JSON/DeviceCompliance/PAW-Compliance-ATP.json) policy is used to feed the Threat Intelligence data from Microsoft Defender for Endpoint into the devices compliance state so its signals can be used as part of the Conditional Access evaluation process.

   2. [Privileged Compliance Delayed](JSON/DeviceCompliance/PAW-Compliance-Delayed.json) policy applies a more complete set of compliance settings to the device but its application is delayed by 24 hours.  this is because the device health attestation that is required to assess policies like BitLocker and Secure Boot is only calculated once a device has rebooted and then might take a number of hours to process whether the device is compliant or not.

   3. [Privileged-Compliance-Immediate](JSON/DeviceCompliance/PAW-Compliance-Immediate.json) policy is used to apply a minimum level of compliance to users and is configured to apply immediately.

[**Import-PAW-DeviceConfiguration.ps1**](Import-PAW-DeviceConfiguration.ps1) - this script is used to import the Device Configuration profiles that harden the Operating System. there are five profiles used:
1.  [Privileged-Config-Win10-Custom-CSP](JSON/DeviceConfiguration/PAW-Win10-Config-Custom-CSP_25-11-2020-17-42-11.json) Applies configuration service provider (CSP) settings that are not available in the Endpoint Manager UI, refer to [Configuration service provider reference](https://docs.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-reference) for the complete list of the CSP settings available.
2.  [Privileged-Config-Win10-Device-Restrictions-UI](JSON/DeviceConfiguration/PAW-Win10-Config-Device-Restrictions-UI_25-11-2020-17-42-11.json) applies settings that restrict cloud account use, configure password policy, Microsoft Defender SmartScreen, Microsoft Defender Antivirus.  Refer to [Windows 10 (and newer) device settings to allow or restrict features using Intune](https://docs.microsoft.com/en-us/mem/intune/configuration/device-restrictions-windows-10) for more details of the settings applied using the profile.
3.  [Privileged-Config-Win10-Endpoint-Protection-UI](JSON/DeviceConfiguration/PAW-Win10-Config-Endpoint-Protection-UI_25-11-2020-17-42-12.json) applies settings that are used to protect devices in endpoint protection configuration profiles including BitLocker, Device Guard, Microsoft Defender Firewall, Microsoft Defender Exploit Guard, refer to [Windows 10 (and later) settings to protect devices using Intune](https://docs.microsoft.com/en-us/mem/intune/protect/endpoint-protection-windows-10?toc=/intune/configuration/toc.json&bc=/intune/configuration/breadcrumb/toc.json) for more details of the settings applied using the profile.
4.  [Privileged-Config-Win10-Identity-Protection-UI](JSON/DeviceConfiguration/PAW-Win10-Config-Identity-Protection-UI_25-11-2020-17-42-13.json) applies the Windows Hello for Business settings to devices, refer to [Windows 10 device settings to enable Windows Hello for Business in Intune](https://docs.microsoft.com/en-us/mem/intune/protect/identity-protection-windows-settings?toc=/intune/configuration/toc.json&bc=/intune/configuration/breadcrumb/toc.json) for more details of the settings applied using the profile.
5.  [PAW-Win10-URLLockProxy-UI](JSON/DeviceConfiguration/PAW-Win10-URLLockProxy-UI_25-11-2020-17-42-13.json) applies the restrictive URL Lock policy to limit the web sites that PAW devices can connect to.
6.  [PAW-Win10-AppLocker-Custom-CSP](JSON/DeviceConfiguration/PAW-Win10-AppLocker-Custom-CSP_25-11-2020-17-42-11.json) applies the Restricted Execution Model policies in enforced mode. The AppLocker configuration is configured to allow applications to run under C:\Program Files, C:\Program Files (x86) and C:\Windows, with user writable paths under blocked. the characteristics for the AppLocker approach is:
    *  Assumption is that users are non-privileged users.
    *  Wherever a user can write they are blocked from executing
    *  Wherever a user can execute they are blocked from writing

7.  [PAW-Win10-Windows-Defender-Firewall-UI](JSON/DeviceConfiguration/PAW-Win10-Windows-Defender-Firewall-UI_29-09-2020-9-50-21.json) applies a Firewall policy that has the following characteristics - all inbound traffic is blocked including locally defined rules the policy includes two rules to allow Delivery Optimization to function as designed. Outbound traffic is also blocked apart from explicit rules that allow DNS, DHCP, NTP, NSCI, HTTP, and HTTPS traffic. This configuration not only reduces the attack surface presented by the device to the network it limits the outbound connections that the device can establish to only those connections required to administer cloud services.

| Rule | Direction | Action | Application / Service | Protocol | Local Ports | Remote Ports |
| --- | --- | --- | --- | --- | --- | --- |
| World Wide Web Services (HTTP Traffic-out) | Outbound | Allow | All | TCP | All ports | 80 |
| World Wide Web Services (HTTPS Traffic-out) | Outbound | Allow | All | TCP | All ports | 443 |
| Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out) | Outbound | Allow | %SystemRoot%\system32\svchost.exe | TCP | 546| 547 |
| Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out) | Outbound | Allow | Dhcp | TCP | 546| 547 |
| Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCP-Out) | Outbound | Allow | %SystemRoot%\system32\svchost.exe | TCP | 68 | 67 |
| Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCP-Out) | Outbound | Allow | Dhcp | TCP | 68 | 67 |
| Core Networking - DNS (UDP-Out) | Outbound | Allow | %SystemRoot%\system32\svchost.exe | UDP | All Ports | 53 |
| Core Networking - DNS (UDP-Out) | Outbound | Allow | Dnscache | UDP | All Ports | 53 |
| Core Networking - DNS (TCP-Out) | Outbound | Allow | %SystemRoot%\system32\svchost.exe | TCP | All Ports | 53 |
| Core Networking - DNS (TCP-Out) | Outbound | Allow | Dnscache | TCP | All Ports | 53 |
| NSCI Probe (TCP-Out) | Outbound | Allow | %SystemRoot%\system32\svchost.exe | TCP | All ports | 80 |
| NSCI Probe - DNS (TCP-Out) | Outbound | Allow | NlaSvc | TCP | All ports | 80 |
| Windows Time (UDP-Out) | Outbound | Allow | %SystemRoot%\system32\svchost.exe | TCP | All ports | 80 |
| Windows Time Probe - DNS (UDP-Out) | Outbound | Allow | W32Time | UDP | All ports | 123 |
| Delivery Optimization (TCP-In) | Inbound | Allow | %SystemRoot%\system32\svchost.exe | TCP | 7680 | All ports |
| Delivery Optimization (TCP-In) | Inbound | Allow | DoSvc | TCP | 7680 | All ports |
| Delivery Optimization (UDP-In) | Inbound | Allow | %SystemRoot%\system32\svchost.exe | UDP | 7680 | All ports |
| Delivery Optimization (UDP-In) | Inbound | Allow | DoSvc | UDP | 7680 | All ports |

> [!NOTE]
> There are two rules defined for each rule in the Microsoft Defender Firewall configuration. To restrict the inbound and outbound rules to Windows Services, e.g. DNS Client, both the service name, DNSCache, and the executable path, C:\Windows\System32\svchost.exe, need to be defined as separate rule rather than a single rule that is possible using Group Policy.


[**Import-PAW-DeviceConfigurationADMX.ps1**](JSON/DeviceConfigurationADMX/Privileged-Edge%20Version%2085%20-%20Computer.json) this script is used to import the Device Configuration ADMX Template profile that configures Microsoft Edge security settings.

1.  [Privileged-Edge Version 85 - Computer](JSON/DeviceConfigurationADMX/Privileged-Edge%20Version%2085%20-%20Computer.json) applies administrative policies that control features in Microsoft Edge version 77 and later, refer to [Microsoft Edge - Policies](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies) or more details of the settings applied using the profile.

