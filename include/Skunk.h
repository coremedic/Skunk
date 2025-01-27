#ifndef SKUNK_SKUNK_H
#define SKUNK_SKUNK_H

#include "Macros.h"
#include "Ntdll.h"

typedef struct {

    struct {
        // Kernel32.dll
        D_API(LoadLibraryW)

        // Ntdll.dll
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

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

#endif //SKUNK_SKUNK_H
