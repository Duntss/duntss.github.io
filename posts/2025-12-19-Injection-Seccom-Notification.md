# Injection Seccom Notification Linux

This article presents a **research-oriented exploration** of Linux process manipulation using **seccomp user notifications**.
The technique described here is **not presented as malware**, but as an educational demonstration of how modern Linux kernel features can be repurposed to influence process execution flow in unexpected ways.
This work is **inspired by and builds upon prior public research**, in particular:

- [_Linux Process Injection via Seccomp Notifier_ by **Kyle Avery (Outflank, 2025)**](https://www.outflank.nl/blog/2025/12/09/seccomp-notify-injection/)

The goal of this article is to provide a **beginner-friendly, step-by-step explanation** of the underlying mechanisms involved, focusing on:

- how seccomp user notifications work,
- how the dynamic linker (`ld.so`) loads shared libraries,
- and how file-descriptor–based redirection can influence this process.

## In Short

This technique leverages **seccomp user notifications** to intercept specific system calls made by a child process during startup.

A parent process first creates an in-memory shared object using `memfd_create`. It then spawns a child process, which installs a seccomp filter and executes a legitimate binary (in this example, `ls`).

When the child process starts, the Linux dynamic linker (`ld.so`) performs a series of `openat()` system calls to load required shared libraries. These calls are intercepted using seccomp user notifications.

The parent selectively allows the first call to proceed normally, but hijacks a subsequent library-loading request by **redirecting it to an in-memory shared object** instead of the intended file on disk.

As a result, the dynamic linker unknowingly maps and executes code from the injected shared object entirely from memory, while the target program (`ls`) continues to execute normally, producing no visible anomalies.

## Complete Exmplanation :
**Phase 1 : Initial Setup (before the injection)**
```
Parent (injector)
|
├─ Create a memfd-backed file containing a malicious ELF shared object (`loader.so`) fully resident in memory.
|
├─ fork() -> Child
|
Child
|
├─ Install the filter seccomp on openat()
├─ Send the FD listener to the parent
└─ execve("/bin/ls") <- Become /bin/ls
```
## Phase 2: Start /bin/ls
```
/bin/ls start
 ↓
Kernel load /lib64/ld-linux-x86-64.so.2 (dynamic linker)
 ↓
ld.so take control to load the dependency
```
### Phase 3: 1st openat() - Let it run
```
ld.so :
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY)
 ↓
Filter seccomp intercepted
 ↓
Kernel SUSPEND /bin/ls
Kernel NOTIFY the parent via listener FD
 ↓
Parent receive notification #1:
  - syscall = openat
  - path = "/etc/ld.so.cache"
  - Tracked via an internal syscall counter associated with the seccomp listener
 ↓
Parent decide : should_hijack_open() → FALSE
  (let run the first notification)
 ↓
Parent reply: SECCOMP_USER_NOTIF_FLAG_CONTINUE
 ↓
Kernel CONTINUE
 ↓
openat() normal execution
 ↓
/bin/ls open /etc/ld.so.cache
```
``/etc/ld.so.cache`` : Cache containing the list of libraries and their paths (to speed up searches). The dynamic linker (`ld.so`) relies on `openat()` when resolving shared library dependencies.

----
### Phase 4: Second openat() - The Injection
```
the ls process continues reading the cache and :
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY)
 ↓
Filter seccomp intercept
 ↓
Kernel SUSPEND /bin/ls
NOTIFY the parent
 ↓
Parent receive the second notification #2:
  - syscall = openat
  - path = "/lib/x86_64-linux-gnu/libc.so.6"
  - The 2nd openat (count = 2)
 ↓
Parent decide : shoudl_hijack_open() → TRUE
 already_injected = false
 ↓
Parent prepare the injection:
  addfd.srcfd = loader_so_fd (memfd with shellcode)
  addfd.flags = SECCOMP_ADDFD_FLAG_SEND
 ↓
Parent do : ioctl(SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) 
 ↓
Kernel :
  1. Take memfd of the parent (loader.so in RAM)
  2. Duplicate the file descriptor into the target process’ file descriptor table.
  3. Choose a number, like FD 7
  4. Return 7 to the parent
 ↓
Parent set : resp->val = 7
Parent set : already_injected = true
 ↓
Kernel run /bin/ls
 ↓
openat() return 7 (and don't open the true libc.so.6)  
```

``SECCOMP_IOCTL_NOTIF_ADDFD`` allows the supervisor process to inject an existing file descriptor directly into the target task’s file descriptor table.

From the perspective of `ld.so`, the returned file descriptor is indistinguishable from a legitimate `libc.so.6`. :
```c
fd = openat("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY); 
// fd = 7 → point to libc.so.6 
// The kernel effectively returns : 
// fd = 7 → point to loader.so (shellcode in RAM)
```

----
### Phase 5 : Loading the shellcode
```
ld.so continue normally
 ↓
ld.so :
  mmap(FD 7, ..., PROT_READ|PROT_EXEC)
 ↓
Kernel map the content of memfd (loader.so) in memory
 ↓
ld.so Parse the ELF headers, program headers (`PT_LOAD`), and relocation entries.:
  - Read the sections .text, .data, .init_array
  - Resolve the symbol
  - Execute the constructors (__attribute__((constructor)))
 ↓
Malicious code execution in .init_array or constructor) 
```
Execution is achieved via `.init_array` entries or ELF constructors, which are invoked automatically by the dynamic linker prior to transferring control to `main()`.

After the injected code executes, the dynamic linker continues loading the remaining libraries normally, and the target program runs without any visible indication of interference.

## Conclusion

This article focused on explaining the underlying mechanics of **seccomp user notifications** and how they can be used to mediate system calls during process startup, from a reverse engineering perspective.

For readers interested in studying a **real-world, publicly available implementation**, the original proof of concept developed by Outflank is available on GitHub. Reviewing the source code provides additional insight into how these kernel primitives are combined in practice and how the supervision logic is implemented at the syscall level.

The repository serves as a useful reference for understanding what such a technique looks like in compiled form and how it may appear during static or dynamic analysis.

**Reference implementation (source code):**
https://github.com/outflanknl/seccomp-notify-injectionv