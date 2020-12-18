# Secure Workstation configuration and policy baselines for Microsoft Intune and Windows 10 




This site is the companion to the Secured Workstation how-to guidance, providing the scripts to deploy the baseline for the Enterprise, Specialized, and Privileged configurations.  

It is highly recommended, that you familiarize yourself with the guidance prior to cloning, or use the files in this repo. Documentation for the solution can be found at - https://aka.ms/securedworkstation


These files are provided as samples, and a starting point to consider when you build your secured solution.

**The scripts has been tested in a EN-US enviroment only, international langugages may require changes to the script for any geo location related errors.**

# Three Security Profiles

1. **Enterprise Security** - is suitable for all enterprise users and productivity scenarios. Enterprise also serves as the starting point for specialized and privileged access as they progressively build on the security controls used in enterprise security configuration. The Enterprise profile has the following characteristics
   * assumes that the user has Privileged rights on the local device
   * allows local Windows Defender Firewall rules to be merged with applied Device Configuration profile settings

    [Enterprise policy settings and deployment script](ENT/Readme.md)

2. **Specialized** - provides increased security controls for roles with a significantly elevated business impact (if compromised by an attacker or malicious insider). The Specialized profile has the highlighted differences from the Enterprise Profile
   * assumes that the user has Standard Privileges on the devices
   * implements Application Execution Control in Audit mode
   * does not merge local Windows Defender Firewall rules
  
    [Specialized policy settings and deployment script](SPE/Readme.md)

3. **Privileged** - is the highest level of security designed for roles that could easily cause a major incident and potential material damage to the organization in the hands of an attacker or malicious insider. This typically includes technical roles with administrative permissions on most or all enterprise systems (and sometimes includes a select few business critical roles). The Privileged profile has the highlighted differences from the Specialized Profile
   * implements Application Execution Control in Enforced mode
   * blocks all outbound connections apart from defined Windows Defender Firewall rules
  
    [Privileged policy settings and deployment script](PAW/Readme.md)

**Legacy** - The content of this directory reflects V1 of Azure Secure Workstation
