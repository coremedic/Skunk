#ifndef SKUNK_SKUNK_H
#define SKUNK_SKUNK_H

#include "Macros.h"
#include "Constexpr.h"
#include "Ntdll.h"

typedef struct {

    struct {
        // Kernel32.dll
        D_API(LoadLibraryA) // Can be replaced with LdrLoadDll

        // Ntdll.dll
        D_API(NtAllocateVirtualMemory)
        D_API(NtProtectVirtualMemory)
        D_API(NtFreeVirtualMemory)
        D_API(LdrLoadDll)
        D_API(LdrGetProcedureAddress)
        D_API(RtlAllocateHeap)
        D_API(RtlFreeHeap)
        D_API(TpAllocWork)
        D_API(TpPostWork)
        D_API(TpReleaseWork)

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
    } Modules;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID RipStart();
EXTERN_C PVOID RipEnd();
EXTERN_C PVOID ProxyCaller();

#endif //SKUNK_SKUNK_H
