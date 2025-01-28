#ifndef SKUNK_LDR_H
#define SKUNK_LDR_H

#include "windows.h"
#include "Skunk.h"
#include "Macros.h"

FUNC PVOID LdrModulePeb(_In_ ULONG moduleHash);
FUNC PVOID LdrFunction(_In_ PVOID module, _In_ ULONG functionHash);

#endif //SKUNK_LDR_H
