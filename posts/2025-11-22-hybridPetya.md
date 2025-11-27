# HybridPetya / NotPetya Deep Dive: Reverse-Engineering & Bootkit Analysis

My IDB (Ida Pro Database) 9.2 are available on my github !

**SHA-256:** HybridPetya.exe `ccdad8f0f97fc54d7d568414364887dcbe57299257305994ea187c43a7c040a8` [Malshare link](https://malshare.com/sample.php?action=detail&hash=ccdad8f0f97fc54d7d568414364887dcbe57299257305994ea187c43a7c040a8) [IDB avalaible here](https://github.com/Duntss/duntss.github.io/blob/main/posts/ccdad8f0f97fc54d7d568414364887dcbe57299257305994ea187c43a7c040a8.bin.i64)
**SHA-256:** DLL extracted : `23fba6c00f0aa812901cd7076cae63270ef34a077154b008a5beef755b1d7c7a` [Malshare link](https://malshare.com/sample.php?action=detail&hash=23fba6c00f0aa812901cd7076cae63270ef34a077154b008a5beef755b1d7c7a) [IDB avalaible here](https://github.com/Duntss/duntss.github.io/blob/main/posts/HybridPetyadump_pe.bin.i64)
**SHA-256:** EFI extracted : `97bc6da2c387b4b0d6f1f08f4eeeec65359bb66cb23c15e805f68c89493bf1d4` [Malshare link](https://malshare.com/sample.php?action=detail&hash=97bc6da2c387b4b0d6f1f08f4eeeec65359bb66cb23c15e805f68c89493bf1d4) [IDB avalaible here](https://github.com/Duntss/duntss.github.io/blob/main/posts/bootkit_uefi.efi.i64)

This article is a full deep-dive reverse‑engineering walkthrough of the HybridPetya malware sample I analyzed.  
It is inspired by the relaxed, technical blog style of duntss — not a formal CERT report, but still accurate and rigorous.

---

## 1. Executive Summary
Here's what I uncovered when dissecting HybridPetya, a NotPetya-like malware that demonstrates straightforward but effective design choices:
- The EXE acts as a loader: it decrypts an embedded DLL (AES-256-CBC) in memory using standard cryptographic routines.
- That DLL is then loaded reflectively (no LoadLibrary) via a custom loader — a well-known technique in modern malware.
- The internal payload gathers entropy, then installs a bootkit (either UEFI or MBR) depending on the system, and forces a crash/reboot.
- The components are clearly structured and functional, showing competent engineering but relying entirely on established techniques rather than novel innovation.

While none of these techniques are particularly sophisticated by today's standards — AES encryption, reflective loading, and custom loaders have been documented and reused for years — the malware's real strength lies in its operational design: the strategic combination of simple components to achieve maximum destructive impact.

## 2. Introduction

### Why HybridPetya Is Interesting
Petya was originally a MBR-targeting ransomware. NotPetya evolved (or devolved) into a destructive wiper. HybridPetya sits somewhere between: it has ransomware-style persistence, but also the destructive / persistent traits of a wiper + bootkit.

The "Hybrid" part of the name — is due to a mixes Petya's boot-hijacking persistence with NotPetya's destructive intent, but unlike NotPetya (which was purely a wiper disguised as ransomware), HybridPetya actually implements both behaviors depending on configuration or target context.

In other words, it's not just a wiper pretending to be ransomware — it's genuinely capable of acting as either, or both.

### Goals of This Analysis

My mission in this blog post: walk you through exactly how HybridPetya works, stage by stage:

1. Decrypting the internal DLL  
2. Loading it through a Reflective Loader  
3. What the DLL actually does (entropy, payload)  
4. Installing a bootkit (UEFI or BIOS)  
5. Triggering a crash to reboot into the bootkit  

**Analysis setup**:  
- VM with **IDA Pro** (both static + dynamic)  
- x64dbg for memory snapshot / breakpoints  
- IDAPython + Python script for dumping memory

## 3. Initial Static Analysis

### Imports and Entry

Opening the EXE in IDA, you only see one import — **kernel32.dll**. That’s weird for a file of this size, which suggests the real logic is hidden.

### Encrypted Embedded DLL & Custom GetProcAddress

There is a huge red flag in `.data`: the string **"ReflectiveLoader"**. That tells you this binary is doing reflective DLL injection. Indeed, there’s a function called `custom_get_proc_address_sub_E610D0` that:

```c
unsigned int custom_get_proc_address_sub_E610D0()
{
    // Validation of the PE signature
    if (*(_WORD *)((char *)&unk_E6CB68 + PE_base_decrypted) != 0x10B)
        return 0;

    // Parse NT headers
    NT_Header_address = (int *)((char *)start_PE_base +
                        sub_E61060(*(int *)((char *)&e_lfanew + PE_base_decrypted)));

    // Get the Export Address Table
    v1 = (unsigned int *)((char *)start_PE_base + sub_E61060(NT_Header_address[8]));

    // Iterate exports to find target function
    // [...]
}
```
Here’s what it’s doing:

Manually reconstructing IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY, etc.

Using strstr() (or similar) to search for “Reflective_Loader” in exported names

Resolving RVA → VA manually, based on section layout

Some light obfuscation: e.g., byte_ECF14F[i] ^= 15169 % i

So even though the import table is minimal (just kernel32), all the heavy lifting is done after decryption in memory.

## 4. Stage 1 — mw_main(): AES Decryption + Reflective Load

This is where everything starts:

```c
int mw_main()
{
    unsigned int proc_address_ReflectiveLoadersub_E610D0; // eax
    int (*ptr_reflective_loader_fn)(void);                // esi
    int (__stdcall *v2)(_DWORD, int, int *);              // eax
    DWORD flOldProtect2;                 // [esp+10h] [ebp-24h] BYREF
    DWORD flOldProtect;                  // [esp+14h] [ebp-20h] BYREF
    int v6;                              // [esp+18h] [ebp-1Ch] BYREF
    CPPEH_RECORD ms_exc;                 // [esp+1Ch] [ebp-18h]

    v6 = 0;
    flOldProtect = 0;
    flOldProtect2 = 0;
    ms_exc.registration.TryLevel = 0;

    // Copy hardcoded AES-256 key and IV from .data section
    qmemcpy(aes_key_dword_ECFDD4, &unk_E6CB20, sizeof(aes_key_dword_ECFDD4));
    init_vector = dword_E6CB40;
    cpy_40CB44 = dword_E6CB44;
    cpy_40CB48 = dword_E6CB48;
    cpy_40CB4C = dword_E6CB4C;

    // Decrypt embedded DLL (402944 bytes) using AES-256-CBC
    wrap_init_and_decrypt_aes();

    // Resolve ReflectiveLoader function from decrypted PE's export table
    proc_address_ReflectiveLoadersub_E610D0 = custom_get_proc_address_ReflectiveLoadersub_E610D0();

    if ( proc_address_ReflectiveLoadersub_E610D0 )
    {
        // Calculate absolute address: base + RVA
        ptr_reflective_loader_fn = (int (*)(void))((char *)&start_PE_base + proc_address_ReflectiveLoadersub_E610D0);

        // Set RWX permissions on decrypted payload region
        if ( VirtualProtect(&start_PE_base, 402944u, PAGE_EXECUTE_READWRITE, &flOldProtect) )
        {
            // Call ReflectiveLoader to get final payload entry point
            v2 = (int (__stdcall *)(_DWORD, int, int *))ptr_reflective_loader_fn();

            // Execute payload with mode flag "6" (likely MBR infection + file encryption)
            if ( v2 && !v2(0, 6, &v6) )
                v6 = 0;

            // Restore original memory permissions
            VirtualProtect(&start_PE_base, 0x62600u, flOldProtect, &flOldProtect2);
        }
    }

    return v6;
}
```

Takeaways:

- Decrypts ~402,944 bytes (≈ 393 KB) in memory
- Makes that memory page RWX
- Calls a function from the decrypted PE: likely its entry point
- Passes a “mode = 6” flag — probably controlling infection logic (MBR / bootkit)

### Dumping the decrypted DLL

I dumped the decrypted DLL using IDAPython:
```c
import idc
import idaapi

start = 0xE6CB50
size = 402944  # dump size

with open("HybridPetya_dump.bin", "wb") as f:
    for i in range(size):
        byte = idc.get_wide_byte(start + i)
        f.write(bytes([byte]))

print("Dump done!")
```
If you don’t have IDA Python, you can set a breakpoint after `VirtualProtect` in x64dbg and dump memory manually.

## 5. Stage 2 – Reflective Loader

Once the DLL is decrypted, the Reflective Loader takes over. But this is not a toy loader — it’s a full-fledged PE loader written from scratch.

### Locating the module base

It doesn’t rely on passed-in pointers. Instead, it searches backwards from the stack pointer until it finds an MZ header:
```c
for ( i = sub_100046C0(); ; --i ) {
    if ( *(_WORD *)i == 'ZM' ) {
        var_e_lfanew = *(_DWORD *)(i + 60);
        if ((unsigned int)(var_e_lfanew - 64) <= 0x3BF && *(_DWORD *)(var_e_lfanew + i) == 'EP')
            break;
    }
}
```
### Resolving APIs via PEB & ROR13 hashing

Instead of using standard API calls, the loader walks through ``PEB->Ldr->InMemoryOrderModuleList`` and computes a **ROR13 hash** on module names and function names to find:

- LoadLibraryA → ``0xEC0E4E8E``
- GetProcAddress → ``0x7C0DFCAA``
- VirtualAlloc → ``0x91AFCA54``
- FlushInstructionCache → ``0x534C0AB8``
Then it parses the **Export Address Table** manually and patches its own IAT.

### Rebuilding the PE in memory

Here’s how it reconstructs the PE:
1. Allocate SizeOfImage bytes with PAGE_EXECUTE_READWRITE
2. Copy DOS header, NT headers, section headers, and each section to the correct VA
3. Apply base relocations if the new base is not the preferred one
4. Resolve imports (by name or ordinal)
5. Flush instruction cache and call entry point (DllMain)

Some extracted code:
```c
// Allocate memory for the PE image
v28 = ((int (__stdcall *)(...))v64)(v1, SizeOfImage, 12288, 64);

// Copy section by section
v33 = *(unsigned __int16 *)(v27 + 6);  // NumberOfSections
do {
    v35 = *(v34 - 1);
    v36 = (_BYTE *)(v74 + *(v34 - 2));
    v37 = (_BYTE *)(i + *v34);
    // Copy raw data to virtual address
    v34 += 10;
} while ( v33 );

// Relocations
// for each relocation entry { switch types ... }

// Call the entry point
v59 = ( … )(v39 + *(_DWORD *)(v27 + 40));  // EntryPoint
FlushInstructionCache(-1, 0, 0);
v59(v39, 1, 0);
```

## 6. Stage 3 – DllMain: Entropy Collection & Bootkit Injection
Once loaded, the DLL’s ``DllMain`` runs a bunch of routines:
- It calls a function like ``collect_entropy_sub_1001F640``, which uses ``CryptGenRandom``, Intel RDRAND, memory stats (heap, modules, threads), SMB stats, process / thread information, etc. The goal is to generate a unique key per victim.
- It calls ``injection_bootkit()``, which is responsible for persistence via bootkit — either UEFI or MBR.

## 7. Bootkit Infection: UEFI & BIOS Legacy

**Overview :**
``injection_bootkit()`` implements a dual-mode persistence:
1. UEFI (64-bit): Replace \EFI\Microsoft\Boot\bootmgfw.efi with a malicious UEFI bootkit
2. BIOS Legacy: Overwrite the MBR, build a malicious bootloader, and persist payload + config on disk

---
### Phase 1: Target System Reconnaissance

- Determines system drive via GetSystemDirectoryA(...)
- Uses DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) to get the physical drive / partition
- Verifies the disk size (if (disk_extent_size / 512 < 40) ExitProcess(0)) — avoids infecting very small volumes
- Uses IsWow64Process to guess whether the machine is 64-bit → uses that to decide between UEFI or BIOS

Code:
```c
h_kernel = GetModuleHandleW(L"kernel32");
v16 = GetProcAddress(h_kernel, "IsWow64Process");
if ( v16 ) {
    CurrentProcess = GetCurrentProcess();
    v16(CurrentProcess, &hDevice);
}

if ( hDevice ) {
    // MODE UEFI
} else {
    // MODE BIOS LEGACY
}
```
### Phase 2: Crypto Prep & Bootkit Decryption

The malware uses a mix of system calls and cryptographic API calls to generate randomness, then decrypts its embedded bootkit:
```c
crypto_func_0(...);
CryptGenRandom(phProv, 8u, pbBuffer);
qmemcpy(&random_data_buffer[1], TokenPrivileges, ...);
qmemcpy(&random_data_buffer[41], btc_address, ...);
memset(v39, 7, sizeof(v39));
```
For decrypting the bootkit:
```c
// Stage 1: decrypt first 512 bytes (MBR or UEFI chunk)
for (i = 0; i < 0x200; byte_1005EFFF[i] ^= v4)
    v4 = 27521 % (int)++i;

// Stage 2: decrypt next 9216 bytes
for (j = 0; j < 0x2400; byte_1005F1FF[j] ^= v6)
    v6 = 27521 % (int)++j;
```
The XOR key for each byte is 27521 % (current_index + offset) — simple, but effective enough to obfuscate the bootkit in the binary.

---

### Strategy A: UEFI Infection
1. The malware parses GPT via ``IOCTL_DISK_GET_DRIVE_LAYOUT_EX``
2. Finds the EFI System Partition using the GUID ``C12A7328-F81F-11D2-BA4B-00A0C93EC93B``
3. Builds a path to the EFI partition:
``\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d\\...``
4. Backs up the original ``bootmgfw.efi`` → ``bootmgfw.efi.old``
5. Decrypts its own EFI bootkit (23,200 bytes)
6. Writes the bootkit to ``bootmgfw.efi``
7. Creates/updates two files in EFI:
    - config (512 bytes): crypto config + bitcoin address
    - verify (512 bytes): buffer of 0x07
Extracted code:
```c
wsprintfA(v47, "\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", disk_number, partition_id);
// … backup + decryption …
WriteFile(FileA, &unk_100556A0, 0x5AA0u, &NumberOfBytesWritten, 0);
```
And for the config / verify :
```c
WriteFile(v27, v41, 0x200u, &v53, 0);  // config
WriteFile(v28, v35, 0x200u, &v51, 0);  // verify
```
### Strategy B: BIOS / MBR Infection
- Reads the original MBR (512 bytes)
- Encrypts it by XOR’ing each byte with 7
- Builds a malicious MBR structure:

|Offset|Size|Content|
|--|--|--|
|0|440|Malicious bootloader code|
|440|68|Original parittion table (kept)|
|510|2|Signature `0xAA55`|

- Writes multiple sectors:
```c
WriteFile(hDevice, v40, 0x200u, …);       // Sector 0 (malicious MBR)
WriteFile(hDevice, dword_1005F200, 0x2400u, …); // Stage 2 bootkit
WriteFile(hDevice, random_data_buffer, 0x200u, …); // Config + BTC
WriteFile(hDevice, v39, 0x200u, …);              // Verify buffer
WriteFile(v11, v42, 0x200u, …);                   // Encrypted original MBR
```

## 8. Triggering BSOD & Reboot

After dropping the bootkit, the malware forces a crash / reboot using:
```c
OpenProcessToken(...);
LookupPrivilegeValueA(..., "SeShutdownPrivilege", …);
AdjustTokenPrivileges(...);

ModuleHandleA = GetModuleHandleA("NTDLL.DLL");
ProcAddress = GetProcAddress(ModuleHandleA, "NtRaiseHardError");
((void (__cdecl *)(...))ProcAddress)(
    STATUS_HOST_DOWN,
    0, 0, 0,
    6,  // OptionShutdownSystem
    v57);
```
It calls NtRaiseHardError with the shutdown option 6 (forced shutdown), causing a BSOD and a reboot — which triggers execution of the just-installed bootkit.

## 9. Extracting & Decrypting the UEFI Bootkit
Here’s the IDAPython script I used to grab and decrypt the UEFI bootkit:
```c
import ida_bytes, idc

def extract_and_decrypt_bootkit():
    bootkit_start = 0x100556A0
    bootkit_size = 0x5AA0

    encrypted = ida_bytes.get_bytes(bootkit_start, bootkit_size)
    decrypted = bytearray()
    k_offset = 1 - bootkit_start

    for i in range(bootkit_size):
        key = (27521 % (bootkit_start + i + k_offset)) & 0xFF
        decrypted.append(encrypted[i] ^ key)

    if decrypted.startswith(b"MZ"):
        print("Valid PE signature")
    else:
        print(f"Header bytes: {decrypted[0:4].hex().upper()}")
        print("No MZ signature — possibly raw UEFI code")

    with open("bootkit_uefi.efi", "wb") as f:
        f.write(decrypted)
    print("Bootkit dumped to bootkit_uefi.efi")

extract_and_decrypt_bootkit()
```
It faithfully reproduces the XOR decryption logic in the malware and writes out a .efi file for further analysis.

## 10. UEFI Bootkit Behavior: Encrypt / Decrypt NTFS
Once the UEFI bootkit runs (at boot), its main function (let's call it ``sub_758``) does the heavy work.

### Initialization & Detection
- Disables the UEFI watchdog timer to prevent reboot during its operation
- Locates the EFI filesystem via ``BootServices->LocateHandleBuffer``
- Opens ``\EFI\Microsoft\Boot\config`` to read infection marker + key
- If the marker doesn’t match the expected value → **first run** → go into *encrypt mode*
- If it matches → **already infected** → go into *decrypt mode*
### Encrypt Mode (First Boot)
- Reads the Bitcoin address (34 bytes) and decryption key (96 bytes) from embedded data
- Displays a ransom screen via PrintString with instructions: “Send … BTC … and key …”
- Reads keyboard input (expecting a 33-char key), handles backspace and enter
- When the key is valid: writes the key to config to avoid asking again later
### Decrypt Mode (After Paying / Valid Key)
- Displays a fake CHKDSK screen to hide its real operations
- Reads NTFS partitions using ReadBlocks
- For each cluster:
    - Decrypts using DecryptBlock(...)
    - Writes decrypted data back with WriteBlocks
- Maintains a counter of clusters processed, saved in \EFI\Microsoft\Boot\counter so that if reboot happens, it can resume where it left off
Code snippet for the loop:
```c
do {
    BlockIoProtocol->ReadBlocks(..., qword_4ED8);

    DecryptBlock(&qword_57C0, &qword_5560, qword_4ED8, (unsigned __int16)word_57E8 << 9);

    BlockIoProtocol->WriteBlocks(..., qword_4ED8);

    ++qword_48D0;
    RootDirectory->Open(..., L"\\EFI\\Microsoft\\Boot\\counter", …);
    CounterFile->Write(..., &qword_48D0);
    CounterFile->Close(CounterFile);

    PrintString("CHKDSK is repairing sector %lld of %lld (%d%%)", qword_4EC8, qword_57E0, 100 * qword_4EC8 / (unsigned __int64)qword_57E0);
} while ( qword_4EC8 <= (unsigned __int64)qword_57E0 );
```
The persistent counter lets the bootkit resume decryption in case of interruptions (power loss, reboot).

## Conclusion

When you look at HybridPetya with a modern reverse-engineering background, it becomes obvious that the malware is not particularly sophisticated on a technical level. Most of its components — AES encryption in memory, PEB walking, simple ROR-based obfuscation, reflective loading, and a custom loader — are all common techniques that have been widely used for years.

The userland side is straightforward: no advanced evasion, no complex cryptography, no heavily obfuscated logic. Nothing here reaches the level of truly advanced implants.

What makes HybridPetya effective is not deep technical brilliance but smart operational design:
- AES decryption in memory
- Reflective DLL loading
- Manual API resolution (PEB walking + ROR13 hash)
- A full custom loader capable of relocation, import resolution, entry point execution
- Bootkit persistence (UEFI + MBR)
- A forced BSOD to ensure its bootkit runs on reboot

So while HybridPetya is far from a masterpiece of malware engineering, it is a strong example of how simple techniques, combined with the right strategic intent, can cause massive real-world impact.
