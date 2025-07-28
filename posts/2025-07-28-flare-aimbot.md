---
layout: post
title: "Flare-10 Aimbot"
---

### Files

| Name       | SHA265                                                           |
| ---------- | ---------------------------------------------------------------- |
| aimbot.exe | 0689f20e973f5834145bf5946f417c3796a891f5a37dddb1430d32895277195b |
### Summary

- aimbot.exe inject into the [game cube 2: sauerbraten](http://sauerbraten.org/) aimbot.dll and dropping a Monero miner.
    - aimbot.dll create 3 thread and have 5 stages of shellcode acessing to (Steam, Discord, Sparrow, Sauerbraten)

### Static Analysis of `aimbot.exe`

Using tools like **Malcat** or **PeStudio**, we can observe that `aimbot.exe` contains **three resources**, each with **high entropy**, which typically indicates **encrypted or packed data**:
![[Pasted image 20250714174608.png]]

---

     Tips :
Normal use of IDA here cause the .exe is not offuscated, the plugin [Flare-Capa](https://github.com/mandiant/capa) can help you to do a faster analysis.

---
### AES Decryption Logic

If the target game (e.g., `sauerbraten`) is running, the program creates a folder under `%APPDATA%` and decrypts each resource using **AES** with a hardcoded key:
![[Pasted image 20250714175035.png]]

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