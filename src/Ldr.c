#include "Ldr.h"
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

FUNC PIMAGE_NT_HEADERS LdrpImgNtHeaders(_In_ PVOID image) {
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
    if (!(ntHeader = LdrpImgNtHeaders(module))) {
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
        // https://devblogs.microsoft.com/oldnewthing/20060719-24/?p=30473
        break;
    }

    return address;
}

FUNC SIZE_T StrToWStr(PWCHAR dst, PCHAR src) {
    INT len = MAX_PATH;

    while (--len >= 0) {
        if (!(*dst++ = *src++)) {
            return MAX_PATH - len -1;
        }
    }
    return MAX_PATH - len;
}

FUNC SIZE_T StrLen(const CHAR* str) {
    const CHAR* s;
    for (s = str; *s; ++s) {}
    return (s - str);
}

FUNC PVOID MemCopy(PVOID dest, const VOID* src, SIZE_T n) {
    // Volatile cast
    volatile PCHAR volDest = (volatile PCHAR)dest;
    volatile const CHAR* volSrc = (volatile const CHAR*)src;

    // Copy memory
    while (n--) {
        *volDest++ = *volSrc++;
    }

    return volDest;
}


FUNC VOID LdrResolveIAT(_In_ PINSTANCE pInstance, _In_ PVOID pMemAddr, _In_ PVOID IatBase) {
    PIMAGE_THUNK_DATA           pOrgThunkData   = NULL,
                                pFirstThunkData = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    pImgImpDesc     = NULL;
    PIMAGE_IMPORT_BY_NAME       pImgImpName     = NULL;
    PCHAR                       pModuleName     = NULL;
    HMODULE                     hModule         = NULL;
    PVOID                       pFunction       = NULL;
    ANSI_STRING                 ansiString      = {0};

    // Loop through IAT
    for (pImgImpDesc = IatBase; pImgImpDesc->Name != 0; ++pImgImpDesc) {
        pModuleName = C_PTR(pMemAddr + pImgImpDesc->Name);
        pOrgThunkData = C_PTR(pMemAddr + pImgImpDesc->OriginalFirstThunk);
        pFirstThunkData = C_PTR(pMemAddr + pImgImpDesc->FirstThunk);

        // Process module name
        //WCHAR wModuleName[MAX_PATH] = {0};
        //StrToWStr(wModuleName, pModuleName);

        // Check if module is already loaded, if not, load it
        if (!(hModule = pInstance->Win32.LoadLibraryA(pModuleName))) {
            // Failed to load module... good luck!
            __debugbreak();
            return;
        }
//        if (!(hModule = LdrModulePeb(HashStringW(wModuleName)))) {
//            // Module not loaded, lets load it
//            if (!(hModule = pInstance->Win32.LoadLibraryA(pModuleName))) {
//                // Failed to load module... good luck!
//                return;
//            }
//        }

        // Loop through imported functions within this module
        for (; pOrgThunkData->u1.AddressOfData != 0; ++pOrgThunkData, ++pFirstThunkData) {
            if (IMAGE_SNAP_BY_ORDINAL(pOrgThunkData->u1.Ordinal)) {
                if (NT_SUCCESS(pInstance->Win32.LdrGetProcedureAddress(hModule, NULL, IMAGE_ORDINAL(pOrgThunkData->u1.Ordinal), &pFunction))) {
                    pFirstThunkData->u1.Function = U_PTR(pFunction);
                }
            } else {
                pImgImpName = C_PTR(U_PTR(pMemAddr) + pOrgThunkData->u1.AddressOfData);
                {
                    ansiString.Length = StrLen(pImgImpName->Name);
                    ansiString.MaximumLength = ansiString.Length + sizeof(CHAR);
                    ansiString.Buffer = pImgImpName->Name;
                }

                if (NT_SUCCESS(pInstance->Win32.LdrGetProcedureAddress(hModule, &ansiString, 0, &pFunction))) {
                    pFirstThunkData->u1.Function = U_PTR(pFunction);
                }
            }
        }
    }
}

FUNC VOID LdrRelocateSections(_In_ PVOID pMemAddr, _In_ PVOID pBeacon, _In_ PVOID pBaseReloc) {
    PIMAGE_BASE_RELOCATION      pImgBaseReloc   = C_PTR(pBaseReloc);
    LPVOID                      pOffset         = C_PTR(U_PTR(pMemAddr) - U_PTR(pBeacon));
    PIMAGE_RELOC                pImgReloc       = NULL;

    while (pImgBaseReloc->VirtualAddress != 0) {
        pImgReloc = (PIMAGE_RELOC) (pImgBaseReloc + 1);

        while ((PBYTE) pImgReloc != (PBYTE) pImgBaseReloc + pImgBaseReloc->SizeOfBlock) {
            if (pImgReloc->type == IMAGE_REL_TYPE) {
                *(ULONG_PTR*) (U_PTR(pMemAddr) + pImgBaseReloc->VirtualAddress + pImgReloc->offset) += (ULONG_PTR) pOffset;
            } else if (pImgReloc->type != IMAGE_REL_BASED_ABSOLUTE) {
                __debugbreak();
                continue;
            }
            pImgReloc++;
        }
        pImgBaseReloc = (PIMAGE_BASE_RELOCATION) pImgReloc;
    }
}
