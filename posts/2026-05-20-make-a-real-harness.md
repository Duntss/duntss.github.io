# From Reverse Engineering to Fuzzer in an Hour: Targeting SteamService's VDF Parser

---

## 1. Context: Why SteamService and Why the VDF Parser?

- **SteamService.exe** runs as a Windows service (often as SYSTEM or elevated), making it a high-priority Bug Bounty target.
- **VDF (Valve Data Format)** is Valve's proprietary text format, similar to JSON, used extensively by Steam for app manifests, configs, and ACLs. It is a key/value format with nested sections delimited by `{` and `}`.
- VDF is **parsed from untrusted sources** (downloaded files, network data) — an interesting attack surface.
- Example of a valid VDF file (base corpus):
  ```
  "2380740"
  {
  }
  ```
  The app ID 2380740 corresponds to a Steam game. Valve exposes VDF files through its public API, which is convenient for building an initial corpus.

---

## 2. Reverse Engineering in IDA: Finding and Understanding the Target Function

### 2.1 Locating the Target Function

- Search for the strings `"{"`, `"//"` (VDF comments), or references to `isspace` in the binary.
- A call to `isspace` inside a parsing loop, combined with a recursive structure (depth parameter), quickly identifies the function.
- **RVA found: `0x058F70`** (= IDA address − module imagebase).

To compute the RVA: `ida_address - imagebase`. In IDA, the imagebase is visible under Edit → Segments → Rebase, or in the PE header. This is what we use to dynamically resolve the function at runtime.

### 2.2 Identifying the Calling Convention

- IDA identifies `__fastcall`: the first two arguments are passed via `ECX` and `EDX` (x86 32-bit). However, closer analysis confirms the function is `__thiscall` — `this` passes via `ECX`, and additional arguments go on the stack.
- Reconstructed signature: `char __thiscall ParseVDF(void* thisptr, int depth)`
- The first argument (`ECX`) is a `this` pointer → this is a C++ method (non-virtual but called on an object).

### 2.3 Reconstructing the VDFParser Structure

By analysing memory accesses on `thisptr` in IDA (offsets used by the code):

| Offset | Type      | Role                                          |
|--------|-----------|-----------------------------------------------|
| +0x00  | `void**`  | Pointer to the vtable                         |
| +0x04  | `char*`   | `cursor` — current position in the buffer     |
| +0x08  | `char*`   | `buf_start` — start of the buffer             |
| +0x0C  | `char*`   | `buf_end` — end of the buffer                 |
| +0x10  | `uint32`  | `abort_flag` — abort flag (set by onError)    |
| +0x14  | `uint32`  | `flag_abort2` — secondary abort flag          |
| +0x18  | `uint32`  | padding                                       |
| +0x1C  | `uint32`  | internal field                                |
| +0x20  | `uint32`  | internal field                                |

Total size: **36 bytes** — verified against IDA's struct view.

The technique: look at every `mov eax, [ecx+X]` and `mov [ecx+X], eax` instruction to reconstruct the layout. IDA allows creating a struct and applying it directly to make the decompiled pseudocode more readable.

### 2.4 Reconstructing the Vtable

The function uses vtable callbacks to notify a "listener" object of parsing events. By following each `call [eax+N*4]`:

| Entry | Vtable offset | Reconstructed signature                                        | Role                      |
|-------|--------------|----------------------------------------------------------------|---------------------------|
| 0     | +0x00        | (destructor, never called by VDF_parsing)                      | Destructor                |
| 1     | +0x04        | `uint8 __fastcall beginSection(void*, int, char* key)`         | Section open `{`          |
| 2     | +0x08        | `uint8 __fastcall endSection(void*, int, char* key)`           | Section close `}`         |
| 3     | +0x0C        | `uint8 __fastcall keyValue(void*, int, char* key, char* val)`  | Key/value pair found      |
| 4     | +0x10        | `void __fastcall onError(void*, int)`                          | Parse error               |

The callbacks return `uint8` (bool) — if `0`, parsing stops. For the harness, `beginSection`, `endSection`, and `keyValue` always return `1` to let the parser run to completion on any input.

---

## 3. Building the Harness

> Full source: [code_first_harness.cpp](https://github.com/Duntss/duntss.github.io/blob/main/posts/code_first_harness.cpp)

### 3.1 WinAFL Harness Philosophy

WinAFL (the Windows port of AFL) instruments the binary via DynamoRIO. It expects:
- An **exported function** (`fuzz_one_input`) taking `(const uint8_t* data, size_t size)`.
- The function must be **re-entrant**: cleanly re-initialised on each iteration, with no residual state.
- A `main()` for standalone testing (validating that the harness runs before launching AFL).

### 3.2 Calling a Function Inside a Third-Party EXE

SteamService.exe is not a DLL — it is an EXE. The module is loaded dynamically and the absolute address is computed from the RVA:

```cpp
HMODULE hMod = LoadLibraryA("SteamService.exe");
pfn = (pfn_ParseVDF)((uintptr_t)hMod + 0x058F70);
```

`LoadLibraryA` on an EXE maps the PE into memory and resolves imports — the process is not launched, only the code is loaded. Resolution is done once in `main()` (stored in a global) to avoid any cost per iteration.

### 3.3 Re-initialising the Parser Object on Each Iteration

The object is **allocated on the stack** (`VDFParser parser;`) and `memset` to zero before each call. This is critical for WinAFL: if state lives in a global, iterations contaminate each other.

```cpp
VDFParser parser;
memset(&parser, 0, sizeof(parser));
parser.vtable    = s_vtable;
parser.cursor    = s_work_buf;
parser.buf_start = s_work_buf;
parser.buf_end   = s_work_buf + size;
// abort_flag = 0 (guaranteed by memset)
```

### 3.4 The Working Buffer

The parser writes into the buffer (it places `\0` bytes in-place to terminate tokens). The AFL buffer cannot be passed directly (read-only / shared). Instead, data is copied into `s_work_buf` (static, 256 KB) with a guard `\0` at the end.

```cpp
static char s_work_buf[1024 * 256];
memcpy(s_work_buf, data, size);
s_work_buf[size] = '\0';
```

This is a standard pattern for text parser harnesses: the AFL input buffer is immutable, but the parser needs to modify the buffer in-place to set token terminators.

### 3.5 Crash Handling via SEH

The call is wrapped in `__try/__except` to catch access violations without killing the WinAFL process. WinAFL detects crashes via its own monitoring mechanism — the `__except` block simply prevents an unhandled exception from propagating to the Windows handler.

```cpp
__try {
    g_pfn_parse((void*)&parser, 0);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    // WinAFL detects the crash via its internal mechanism
}
```

### 3.6 Exporting the Function for WinAFL

A `.def` file exports `fuzz_one_input`:
```
EXPORTS
    fuzz_one_input
```

The offset of `fuzz_one_input` in `harness.exe` (`0x1070`) is passed to WinAFL via `-target_offset`.

---

## 4. The Reconstructed VDF Parser Pseudocode

The file `VDF_parser.cpp` contains the IDA pseudocode reconstruction. Notable points:

- **Recursive parsing**: `VDF_parsing(this, depth+1)` on `{` → unbounded depth → risk of stack overflow on deeply nested input.
- **Pointer navigation**: the parser advances `this->cursor` directly in the buffer — any bounds-checking bug exposes an out-of-buffer read.
- **Comment handling `//`**: a loop that advances until `\n` — worth checking that end-of-buffer is handled correctly.
- **Abort flag**: `this->abort_flag` checked at the start of each loop iteration → callbacks can trigger a clean stop.

---

## 5. Launching WinAFL

```
afl-fuzz.exe
  -i corpus\
  -o out\
  -t 10000
  -D <DynamoRIO/bin32>
  -w winafl.dll
  --
  -coverage_module harness.exe
  -target_module harness.exe
  -target_offset 0x1070
  -nargs 2
  --
  harness.exe @@
```

`-coverage_module` controls which module is instrumented for coverage. Adding a second `-coverage_module SteamService.exe` also instruments the target binary itself, giving visibility into which parser branches are actually reached.

---

## 6. Debugging Stability — From 40% to 99.29%

### 6.1 What Is Stability in WinAFL?

`stability` in `fuzzer_stats` measures the **reproducibility of the coverage bitmap**: for the same input, is the observed execution path identical across iterations?

- `100%` — perfectly deterministic: every run covers exactly the same blocks.
- `< 80%` — the fuzzer detects too many phantom "new paths" → it spends time saving them instead of mutating inputs; throughput collapses and the corpus bloats.

The internal calculation: WinAFL replays the same input twice and XORs the bitmaps. If bits differ, the iteration is flagged as unstable.

A harness at 40% stability is not really fuzzing — it is spinning in place. Before looking for bugs, pushing stability above 95% is the first priority.

### 6.2 Diagnosis: Sources of Non-Determinism

Common sources of non-determinism in a Windows harness:

| Cause | Symptom |
|---|---|
| DLL initialisation inside `fuzz_one_input` | Startup code (CRT, TLS callbacks, sockets) runs only on the 1st iteration → bitmaps differ between iter 0 and iter N |
| Global state in the target module | Static variables modified by the first call, not reset for subsequent ones |
| ASLR across runs | Different module base addresses per run (rare in WinAFL persistent mode) |
| Threads / timers in the loaded module | Asynchronous code executing randomly between iterations |
| Incorrect calling convention | Stack corruption → undefined behaviour |

In this case, the primary cause was **`LoadLibraryA` being called inside `fuzz_one_input`**.

### 6.3 The Problem: `LoadLibraryA` in the Hot Loop

Initial (unstable, ~40%) version:

```cpp
// WRONG: resolution on every iteration
int fuzz_one_input(const uint8_t* data, size_t size) {
    static pfn_ParseVDF pfn = NULL;
    if (!pfn) {
        HMODULE hMod = LoadLibraryA("SteamService.exe");
        pfn = (pfn_ParseVDF)((uintptr_t)hMod + RVA_VDF_PARSING);
    }
    // ...
}
```

WinAFL instruments `fuzz_one_input` **after** `main()` returns. If `LoadLibraryA` is called inside `fuzz_one_input` during the **first instrumented iteration**, SteamService.exe's initialisation code (TLS callbacks, CRT global init, socket init, etc.) executes once and covers blocks that no subsequent iteration will ever cover. The 1st iteration's bitmap is radically different from all following ones — immediate instability.

### 6.4 Fix 1: Move Resolution to `main()`, Before Instrumentation

```cpp
// CORRECT: resolution in main(), before DynamoRIO instruments fuzz_one_input
static pfn_ParseVDF g_pfn_parse = NULL;

int main(int argc, char** argv) {
    HMODULE hMod = GetModuleHandleA(TARGET_MODULE);
    if (!hMod) hMod = LoadLibraryA(TARGET_MODULE_PATH);
    if (!hMod) hMod = LoadLibraryA(TARGET_MODULE);
    g_pfn_parse = (pfn_ParseVDF)((uintptr_t)hMod + RVA_VDF_PARSING);
    // ...
}
```

`GetModuleHandleA` is tried first: if SteamService.exe is already mapped in the process, it has no side effects and does not trigger any init code. A pre-initialised global is a pure read with no branch in the hot loop, unlike a `static` local with an `if (!pfn)` guard.

Everything with side effects belongs in `main()`, before it returns. `fuzz_one_input` must be as pure as possible — read input, initialise stack object, call, return.

### 6.5 Fix 2: Correct Calling Convention (`__fastcall` → `__thiscall`)

Initial (incorrect) version:

```cpp
// WRONG: __fastcall puts 2nd arg in EDX, polluting it unnecessarily
typedef char (__fastcall *pfn_ParseVDF)(void* thisptr, int unused, int depth);
pfn((void*)&parser, 0, 0);  // 3 args
```

IDA confirms the function is `__thiscall`: `this` passes via `ECX`, and additional arguments pass on the stack (not via `EDX`). With `__fastcall` and 3 args, a 0 is placed in `EDX`, which can corrupt callee-saved registers depending on the function's prologue.

```cpp
// CORRECT: __thiscall — this via ECX, depth on the stack
typedef char (__thiscall *pfn_ParseVDF)(void* thisptr, int depth);
g_pfn_parse((void*)&parser, 0);  // 2 args
```

Even minor stack corruption can alter the parser's behaviour on certain inputs, producing different paths and an unstable bitmap.

### 6.6 Fix 3: Correctly Implement `cb_onError`

The error callback must write `1` at offset `+0x10` of the parser object — that is exactly what `sub_458320` does in SteamService.exe according to IDA. Without this, when the parser encounters a syntax error, it continues advancing through the buffer instead of stopping, leading to unpredictable behaviour.

```cpp
// vtable[4] sub_458320: void __thiscall(_BYTE* this) { *(this+16) = 1; }
static void __fastcall cb_onError(void* self, int) {
    *((uint32_t*)((char*)self + CUTLMEMORY_OFF_ABORT_FLAG)) = 1;
}
```

Each vtable callback has a precise implementation in the original binary. The error callback has a critical side effect: it sets the flag that breaks the parser's main loop. Missing it leaves the parser spinning on malformed inputs, randomising execution paths across iterations.

### 6.7 Fix 4: `__declspec(noinline)` on `fuzz_one_input`

```cpp
__declspec(noinline) __declspec(dllexport)
int fuzz_one_input(const uint8_t* data, size_t size) { ... }
```

Without `noinline`, the compiler may inline `fuzz_one_input` into `main()`. WinAFL locates the function by its offset in the PE (`-target_offset 0x1070`). If the function is inlined, that offset points into the middle of another function — WinAFL instruments the wrong entry point and produces incoherent results.

### 6.8 Static Size Assertion

```cpp
static_assert(sizeof(VDFParser) == CUTLMEMORY_SIZE,
    "VDFParser must be exactly 36 bytes (CUtlMemory)");
```

This costs nothing at runtime but eliminates an entire class of silent bugs: if IDA offsets are mis-transcribed and the struct is 32 or 40 bytes instead of 36, the parser writes `abort_flag` to the wrong offset — unpredictable behaviour on every iteration. The compiler refuses to build if the layout does not match.

### 6.9 Results

After applying all four fixes:

| Metric | Before | After |
|---|---|---|
| `stability` | ~40% | **99.29%** |
| `execs_per_sec` | ~80 | **371** |
| Observed behaviour | Corpus bloat, phantom new paths | Stable mutations, real coverage growth |

The throughput gain (×4.6) comes from two factors:
1. **Elimination of phantom new paths**: WinAFL no longer wastes time saving ghost inputs to the corpus.
2. **Module resolution outside the loop**: `LoadLibraryA` carries non-trivial cost — calling it once in `main()` removes it entirely from the hot path.

Stability and throughput are directly linked: an unstable harness generates false coverage signals, which forces AFL to explore non-existent paths, burning CPU cycles on noise. Fixing stability fixes throughput for free.

---

## 7. Campaign Status and Next Steps

### Current Campaign Statistics

```
execs_per_sec : 371
stability     : 99.29%
```

### Investigation Axes

- **Stack overflow via deep nesting**: build a corpus of `{{{{{...}}}}}` (N levels) to find the limit. The parser is recursive with no explicit maximum depth visible in IDA.
- **Bounds checking on strings**: the parser advances `cursor` without explicitly checking `cursor < buf_end` on certain paths (comments `//`, multiline strings). An input with no trailing `\n` after `//` is worth testing.
- **Secondary coverage**: add `-coverage_module SteamService.exe` to the WinAFL command to also instrument the target binary, giving visibility into which parser branches are actually reached.
- **Enriched corpus**: parse real VDF files from the public Steam API (app manifests, `appinfo.vdf`) to maximise coverage of valid paths before mutating toward invalid ones.

---

## Source Code

The complete harness is available here: [code_first_harness.cpp](https://github.com/Duntss/duntss.github.io/blob/main/posts/code_first_harness.cpp)
