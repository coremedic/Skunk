#ifndef SKUNK_LDR_H
#define SKUNK_LDR_H

#include "windows.h"
#include "Skunk.h"
#include "Macros.h"

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

FUNC PVOID LdrModulePeb(_In_ ULONG moduleHash);
FUNC PVOID LdrFunction(_In_ PVOID module, _In_ ULONG functionHash);
FUNC VOID LdrResolveIAT(_In_ PINSTANCE pInstance, _In_ PVOID pMemAddr, _In_ PVOID IatBase);
FUNC VOID LdrRelocateSections(_In_ PVOID pMemAddr, _In_ PVOID pBeacon, _In_ PVOID pBaseReloc);
FUNC PVOID MemCopy(PVOID dest, const VOID* src, SIZE_T n);

#endif //SKUNK_LDR_H
