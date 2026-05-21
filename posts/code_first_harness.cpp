#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// ── Extracted IDA address (imagebase = 0x400000) ──────────────────────────
#define IMAGEBASE                0x400000UL
#define RVA_VDF_PARSING          0x058F70UL  // VDF_parsing  (abs 0x458F70)
#define RVA_VTABLE_KEYVALUES     0x1EE88CUL  // ??_7CKeyValuesParser@@6B@
#define RVA_VTABLE_INSTALLSCRIPT 0x1EE8A4UL  // ??_7CInstallScriptParser@@6B@

// CUtlMemory offset (struct 36 bytes, 9 element — verified via IDA)
#define CUTLMEMORY_OFF_VTABLE       0x00  // m_pMemory      : 
#define CUTLMEMORY_OFF_CURSOR       0x04  // m_nGrowSize    : 
#define CUTLMEMORY_OFF_BUF_START    0x08  // m_nAllocationCount : 
#define CUTLMEMORY_OFF_BUF_END      0x0C  // fin_buffer     : 
#define CUTLMEMORY_OFF_ABORT_FLAG   0x10  // padding2       : 
#define CUTLMEMORY_OFF_FLAG_ABORT2  0x14  // flag_abort     : 
#define CUTLMEMORY_OFF_PADDING1     0x18  // padding1
#define CUTLMEMORY_OFF_FN_RET0      0x1C  // fn_ret_0
#define CUTLMEMORY_OFF_FN_DISC2     0x20  // fn_to_discover2
#define CUTLMEMORY_SIZE             0x24  // 36 bytes

#define TARGET_MODULE      "SteamService.exe"
#define TARGET_MODULE_PATH "C:\\Program Files (x86)\\Steam\\bin\\SteamService.exe"

// Conventions d'appel x86 uniquement (32-bit) — SteamService.exe est un PE32
#ifndef _M_IX86
#  error "32 bit harness"
#endif

// Exact signature : __thiscall, 2 args (this via ECX, depth on the stack)
typedef char (__thiscall *pfn_ParseVDF)(void* thisptr, int depth);

// ── Vtable ─────────────────
// vtable[1] sub_458300 : char __stdcall(int) { return 1; }
static unsigned __int8 __fastcall cb_beginSection(void* self, int, char* key) {
    return 1;
}
// vtable[2] sub_458300 : same function than beginSection (return 1)
static unsigned __int8 __fastcall cb_endSection(void* self, int, char* key) {
    return 1;
}
// vtable[3] sub_458310 : char __stdcall(int, int) { return 1; }
static unsigned __int8 __fastcall cb_keyValue(void* self, int, char* key, char* val) {
    return 1;
}
// vtable[4] sub_458320 : void __thiscall(_BYTE* this) { *(this+16) = 1; }
static void __fastcall cb_onError(void* self, int) {
    *((uint32_t*)((char*)self + CUTLMEMORY_OFF_ABORT_FLAG)) = 1;
}

// static vtable (5 entry, index 0 = destructor, never called by VDF_parsing)
static void* s_vtable[] = {
    NULL,                    // [0] destructor — not called
    (void*)cb_beginSection,  // [1] onBeginKeyValue
    (void*)cb_endSection,    // [2] onEndKeyValue
    (void*)cb_keyValue,      // [3] onKeyValue
    (void*)cb_onError,       // [4] onError 
};

// ── Layout réel de l'objet parser (CUtlMemory, 36 bytes, vérifié IDA) ────────
typedef struct {
    void**   vtable;       // +0x00  m_pMemory      : vtable ptr
    char*    cursor;       // +0x04  m_nGrowSize    : current position
    char*    buf_start;    // +0x08  m_nAllocationCount : 
    char*    buf_end;      // +0x0C  end_buffer     : 
    uint32_t abort_flag;   // +0x10  padding2       : flag abort 
    uint32_t flag_abort2;  // +0x14  flag_abort     : flag 
    uint32_t padding1;     // +0x18
    uint32_t fn_ret_0;     // +0x1C
    uint32_t fn_to_disc2;  // +0x20
} VDFParser; // sizeof = 36 bytes

// Vérification statique de la taille
static_assert(sizeof(VDFParser) == CUTLMEMORY_SIZE,
    "VDFParser doit faire exactement 36 bytes (CUtlMemory)");

// Working buffer
static char s_work_buf[1024 * 256];

// Global ptr pre resolve by main() - Never NULL when WinAFL call fuzz_one_input
static pfn_ParseVDF g_pfn_parse = NULL;

// ── WinAFL entry point ────────────────────────────────────────────────────
__declspec(noinline) __declspec(dllexport)
int fuzz_one_input(const uint8_t* data, size_t size) {

    if (!g_pfn_parse || size == 0 || size > sizeof(s_work_buf) - 1)
        return 0;

    memcpy(s_work_buf, data, size);
    s_work_buf[size] = '\0';

    // Reinitilisation of the object at each operation (36 bytes)
    VDFParser parser;
    memset(&parser, 0, sizeof(parser));
    parser.vtable    = s_vtable;
    parser.cursor    = s_work_buf;
    parser.buf_start = s_work_buf;
    parser.buf_end   = s_work_buf + size;

    __try {
        g_pfn_parse((void*)&parser, 0);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // WinAFL detect the crash via it's intern mechanism
    }

    return 0;
}

int main(int argc, char** argv) {
    HMODULE hMod = GetModuleHandleA(TARGET_MODULE);
    if (!hMod) hMod = LoadLibraryA(TARGET_MODULE_PATH);
    if (!hMod) hMod = LoadLibraryA(TARGET_MODULE);  // fallback relative path
    if (!hMod) {
        fprintf(stderr, "[-] Failed to load %s (error %lu)\n",
                TARGET_MODULE, GetLastError());
        return 1;
    }
    g_pfn_parse = (pfn_ParseVDF)((uintptr_t)hMod + RVA_VDF_PARSING);
    printf("[+] %s loaded at 0x%p, VDF_parsing at 0x%p\n",
           TARGET_MODULE, (void*)hMod, (void*)g_pfn_parse);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 1;

    DWORD sz = GetFileSize(hFile, NULL);
    uint8_t* buf = (uint8_t*)malloc(sz);
    if (!buf) { CloseHandle(hFile); return 1; }

    DWORD read = 0;
    ReadFile(hFile, buf, sz, &read, NULL);
    CloseHandle(hFile);

    int ret = fuzz_one_input(buf, read);

    free(buf);
    return ret;
}
