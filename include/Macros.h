#ifndef SKUNK_MACROS_H
#define SKUNK_MACROS_H

#define D_TEXT(x)  __attribute__((section(".text$" #x "")))
#define FUNC D_TEXT(B)
#define D_API(x)  __typeof__(x) *x;
#define MemCopy  __builtin_memcpy

// Casting macros
#define C_PTR(x)   ((PVOID) (x))
#define U_PTR(x)   ((UINT_PTR) (x))

// Dereference macros
#define C_DEF(x)   (*(PVOID*) (x))

// IDE macros
#ifdef  __cplusplus

#define CONSTEXPR         constexpr
#define INLINE            inline
#define STATIC            static
#define EXTERN            extern

#else

#define CONSTEXPR
#define INLINE
#define STATIC
#define EXTERN

#endif

#endif //SKUNK_MACROS_H
