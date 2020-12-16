
# LEGACY V1 - Secure Workstation configuration and policy baselines for Microsoft Intune and Windows RS5 

**Content of this folder is provided as solution history...**

Supporting document - https://aka.ms/securedworkstation


This site is a companion to the Secured Workstation providing the baseline for the 5 sceanrio levels outlined in document.

These files are provided as samples, and a starting point to consider when you build your secured solution. 

**Note** The scripts have been tested in a EN-US enviroment only, as locality may impact international langugage packs.

# 6 sceanrios

1. **Low Security** - No baseline provided
2. **Enhanced Security** - Enhanced Workstation - Windows10 (1809) .ps1
3. **High Security** - High Security Workstation - Windows10 (1809) .ps1 
4. **Specialized** - Specialized workstation utilizes the [NCSC Security baseline](https://github.com/pelarsen/IntunePowerShellAutomation/blob/master/DeviceConfiguration_NCSC%20-%20Windows10%20(1803)%20SecurityBaseline.ps1) and the addition of the compliance enforcement script DeviceCompliance_NCSC-Windows10(1803).ps1
5. **Secured** - Secure Workstation - Windows10 (1809) SecurityBaseline (90).ps1
6. **Isolated** - No additional baseline provided


# MMA client installer 

The InstallMMAforApplocker.ps1 file will download and install MMA client for monitoring. This is part of the applocker monitoring provided in the Specialized, and Secured workstation sceanrios. The data will be uploaded to Log Analytics.
