#include "Ldr.h"
#include "Macros.h"
#include "Ntdll.h"
#include "Constexpr.h"

FUNC PVOID LdrModulePeb(_In_ ULONG moduleHash) {
    PLDR_DATA_TABLE_ENTRY pLdrData  = NULL;
    PLIST_ENTRY           pHead     = NULL;
    PLIST_ENTRY           pEntry    = NULL;
    PEB*                  pPeb      = NULL;

    // Fetch current PEB
    pPeb = NtCurrentPeb();

    // Fetch loaded module list
    pHead  = &pPeb->Ldr->InLoadOrderModuleList;
    pEntry = pHead->Flink;

    // Loop through loaded modules to find target module
    for (; pHead != pEntry; pEntry = pEntry->Flink) {
        pLdrData = C_PTR(pEntry);
        if (HashStringW(pLdrData->BaseDllName.Buffer) == moduleHash) {
            // Module found return base address
            return pLdrData->DllBase;
        }
    }

    // Module not found in PEB
    return NULL;
}

FUNC PIMAGE_NT_HEADERS LdrImgNtHeaders(_In_ PVOID image) {
    PIMAGE_DOS_HEADER pImgDosHdr = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;

    // DOS headers are at start of image
    pImgDosHdr = (PIMAGE_DOS_HEADER)C_PTR(image);
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    // Traverse PEB to reach NT headers
    pImgNtHdrs = (PIMAGE_NT_HEADERS)C_PTR(U_PTR(image) + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    return pImgNtHdrs;
}

FUNC PVOID LdrFunction(_In_ PVOID module, _In_ ULONG functionHash) {
    PVOID                   address    = {0};
    PIMAGE_NT_HEADERS       ntHeader   = {0};
    PIMAGE_EXPORT_DIRECTORY expDir     = {0};
    PDWORD                  addrNames  = {0};
    PDWORD                  addrFuncs  = {0};
    PWORD                   addrOrdns  = {0};
    PCHAR                   funcName   = {0};

    if (!module || !functionHash) {
        return NULL;
    }

    // Fetch module NT headers
    if (!(ntHeader = LdrImgNtHeaders(module))) {
        return NULL;
    }

    // Fetch EAT
    expDir     = (PIMAGE_EXPORT_DIRECTORY)C_PTR(module + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    addrNames  = (PDWORD)C_PTR(module + expDir->AddressOfNames);
    addrFuncs  = (PDWORD)C_PTR(module + expDir->AddressOfFunctions);
    addrOrdns  = (PWORD)C_PTR(module + expDir->AddressOfNameOrdinals);

    // Parse EAT
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {

        // Compare function name with hash
        funcName = (PCHAR)C_PTR(U_PTR(module) + addrNames[i]);
        if (HashStringA(funcName) != functionHash) {
            continue;
        }

        // Fetch function pointer
        address = C_PTR(U_PTR(module) + addrFuncs[addrOrdns[i]]);

        // Edge case: forwarded functions... likely don't need them
        break;
    }

    return address;
}