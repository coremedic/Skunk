#ifndef SKUNK_CONSTEXPR_H
#define SKUNK_CONSTEXPR_H

#include <windows.h>
#include "Macros.h"

#define HASHA(string) HashStringA((string))
#define HASHW(wstring) HashStringW((wstring))

CONSTEXPR ULONG CompileTimeSeed() {
    return	(__TIME__[7] - '0') * 1ULL    +
              (__TIME__[6] - '0') * 10ULL   +
              (__TIME__[4] - '0') * 60ULL   +
              (__TIME__[3] - '0') * 600ULL  +
              (__TIME__[1] - '0') * 3600ULL +
              (__TIME__[0] - '0') * 36000ULL;
};

#define H_SEED   500 //(CompileTimeSeed() % 254)
#define H_KEY    6

CONSTEXPR ULONG HashStringA(PCHAR string) {
    ULONG hash = H_SEED;
    CHAR  c    = 0;

    if (!string) {
        return 0;
    }

    while ((c = *string++)) {
        // Convert to uppercase
        c = (c >= 'a' && c <= 'z') ? c - 32 : c;

        // SDBM algorithm
        hash = (UINT8)c + (hash << H_KEY) + (hash << 16) - hash;
    }
    return hash;
}


CONSTEXPR ULONG HashStringW(PWCHAR wstring) {
    ULONG hash = H_SEED;
    WCHAR wc   = 0;

    if (!wstring) {
        return 0;
    }

    while ((wc = *wstring++)) {
        // Convert to uppercase
        wc = (wc >= L'a' && wc <= L'z') ? wc - 32 : wc;

        // SDBM algorithm
        hash = (UINT32)wc + (hash << H_KEY) + (hash << 16) - hash;
    }
    return hash;
}

#endif //SKUNK_CONSTEXPR_H
