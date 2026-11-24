#include <windows.h>
#include <intrin.h>

/*
 * Searches DLLs already loaded in the current process, in loader-list order.
 * Names are case-sensitive; forwarded exports and API-set contracts are
 * resolved without loading additional DLLs. API-set schema version 6 is used
 * by Windows 10 and later. Returns NULL when resolution is not possible.
 *
 * This code reads undocumented Windows loader structures. The caller must
 * prevent DLL unloads while resolving and using the returned address.
 *
 * There are no global or static variables; static functions have internal
 * linkage only. MSVC options tested: /O2 /Gy- /GS- /Zl /c. Inspect the
 * resulting object and linked image when changing compiler options: compiler
 * instrumentation or optimizations can introduce external dependencies.
 * /GS- disables stack-cookie protection. On x64 the compiler also emits
 * unwind metadata in .pdata and .xdata; keeping only .text does not preserve
 * Windows stack unwinding. Object-file relocations must be resolved by linking.
 */

#if defined(_M_X64)
#pragma intrinsic(__readgsqword)
#define PEB_LDR_OFFSET       0x18
#define PEB_API_SET_OFFSET   0x68
#define LDR_LIST_OFFSET      0x20
#define ENTRY_LINK_OFFSET    0x10
#define ENTRY_BASE_OFFSET    0x30
#define ENTRY_NAME_OFFSET    0x58
#elif defined(_M_IX86)
#pragma intrinsic(__readfsdword)
#define PEB_LDR_OFFSET       0x0c
#define PEB_API_SET_OFFSET   0x38
#define LDR_LIST_OFFSET      0x14
#define ENTRY_LINK_OFFSET    0x08
#define ENTRY_BASE_OFFSET    0x18
#define ENTRY_NAME_OFFSET    0x2c
#else
#error This implementation supports MSVC x86 and x64 only.
#endif

typedef struct GP_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} GP_UNICODE_STRING;

typedef struct GP_API_SET_NAMESPACE {
    ULONG Version, Size, Flags, Count, EntryOffset, HashOffset, HashFactor;
} GP_API_SET_NAMESPACE;

typedef struct GP_API_SET_ENTRY {
    ULONG Flags, NameOffset, NameLength, HashedLength, ValueOffset, ValueCount;
} GP_API_SET_ENTRY;

typedef struct GP_API_SET_VALUE {
    ULONG Flags, NameOffset, NameLength, ValueOffset, ValueLength;
} GP_API_SET_VALUE;

static BYTE *gp_peb(void)
{
#if defined(_M_X64)
    return (BYTE *)(ULONG_PTR)__readgsqword(0x60);
#else
    return (BYTE *)(ULONG_PTR)__readfsdword(0x30);
#endif
}

static int gp_range(SIZE_T size, SIZE_T offset, SIZE_T count, SIZE_T unit)
{
    return offset <= size && unit != 0 && count <= (size - offset) / unit;
}

static unsigned int gp_lower(unsigned int c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static SIZE_T gp_trim_dll(const char *s, SIZE_T n)
{
    if (n >= 4 && s[n - 4] == '.' &&
        gp_lower((unsigned char)s[n - 3]) == 'd' &&
        gp_lower((unsigned char)s[n - 2]) == 'l' &&
        gp_lower((unsigned char)s[n - 1]) == 'l')
        return n - 4;
    return n;
}

static SIZE_T gp_trim_wdll(const WCHAR *s, SIZE_T n)
{
    if (n >= 4 && s[n - 4] == L'.' &&
        gp_lower(s[n - 3]) == 'd' && gp_lower(s[n - 2]) == 'l' &&
        gp_lower(s[n - 1]) == 'l')
        return n - 4;
    return n;
}

static int gp_ascii_wide_equal(const char *a, SIZE_T an,
                               const WCHAR *b, SIZE_T bn)
{
    SIZE_T i;
    an = gp_trim_dll(a, an);
    bn = gp_trim_wdll(b, bn);
    if (an != bn)
        return 0;
    for (i = 0; i < an; ++i)
        if (gp_lower((unsigned char)a[i]) != gp_lower(b[i]))
            return 0;
    return 1;
}

static int gp_wide_equal(const WCHAR *a, SIZE_T an, const WCHAR *b, SIZE_T bn)
{
    SIZE_T i;
    an = gp_trim_wdll(a, an);
    bn = gp_trim_wdll(b, bn);
    if (an != bn)
        return 0;
    for (i = 0; i < an; ++i)
        if (gp_lower(a[i]) != gp_lower(b[i]))
            return 0;
    return 1;
}

static LIST_ENTRY *gp_loader_list(void)
{
    BYTE *peb = gp_peb();
    BYTE *ldr = peb ? *(BYTE **)(peb + PEB_LDR_OFFSET) : NULL;
    return ldr ? (LIST_ENTRY *)(ldr + LDR_LIST_OFFSET) : NULL;
}

static BYTE *gp_entry(LIST_ENTRY *link)
{
    return (BYTE *)link - ENTRY_LINK_OFFSET;
}

static BYTE *gp_find_module(const char *name, SIZE_T length)
{
    LIST_ENTRY *head = gp_loader_list(), *link;
    if (!head)
        return NULL;
    for (link = head->Flink; link != head; link = link->Flink) {
        BYTE *entry = gp_entry(link);
        GP_UNICODE_STRING *base_name = (GP_UNICODE_STRING *)(entry + ENTRY_NAME_OFFSET);
        if (base_name->Buffer &&
            gp_ascii_wide_equal(name, length, base_name->Buffer,
                                base_name->Length / sizeof(WCHAR)))
            return *(BYTE **)(entry + ENTRY_BASE_OFFSET);
    }
    return NULL;
}

static BYTE *gp_find_wide_module(const WCHAR *name, SIZE_T length)
{
    LIST_ENTRY *head = gp_loader_list(), *link;
    if (!head)
        return NULL;
    for (link = head->Flink; link != head; link = link->Flink) {
        BYTE *entry = gp_entry(link);
        GP_UNICODE_STRING *base_name = (GP_UNICODE_STRING *)(entry + ENTRY_NAME_OFFSET);
        if (base_name->Buffer &&
            gp_wide_equal(name, length, base_name->Buffer,
                          base_name->Length / sizeof(WCHAR)))
            return *(BYTE **)(entry + ENTRY_BASE_OFFSET);
    }
    return NULL;
}

static GP_UNICODE_STRING *gp_module_name(BYTE *module)
{
    LIST_ENTRY *head = gp_loader_list(), *link;
    if (!head)
        return NULL;
    for (link = head->Flink; link != head; link = link->Flink) {
        BYTE *entry = gp_entry(link);
        if (*(BYTE **)(entry + ENTRY_BASE_OFFSET) == module)
            return (GP_UNICODE_STRING *)(entry + ENTRY_NAME_OFFSET);
    }
    return NULL;
}

static int gp_api_set_equal(const char *name, SIZE_T length,
                            const WCHAR *entry_name, SIZE_T entry_length,
                            SIZE_T hashed_length)
{
    SIZE_T end, i;
    length = gp_trim_dll(name, length);
    if (gp_ascii_wide_equal(name, length, entry_name, entry_length))
        return 1;
    end = length;
    while (end && name[end - 1] >= '0' && name[end - 1] <= '9')
        --end;
    if (end == length || !end || name[end - 1] != '-' ||
        hashed_length != end - 1 || hashed_length > entry_length)
        return 0;
    for (i = 0; i < hashed_length; ++i)
        if (gp_lower((unsigned char)name[i]) != gp_lower(entry_name[i]))
            return 0;
    return 1;
}

static BYTE *gp_api_set_module(const char *name, SIZE_T length, BYTE *importer)
{
    BYTE *peb = gp_peb(), *map;
    GP_API_SET_NAMESPACE *ns;
    GP_UNICODE_STRING *importer_name = gp_module_name(importer);
    ULONG i, j;
    if (!peb)
        return NULL;
    map = *(BYTE **)(peb + PEB_API_SET_OFFSET);
    if (!map)
        return NULL;
    ns = (GP_API_SET_NAMESPACE *)map;
    if (ns->Version != 6 || ns->Size < sizeof(*ns) ||
        !gp_range(ns->Size, ns->EntryOffset, ns->Count, sizeof(GP_API_SET_ENTRY)))
        return NULL;

    for (i = 0; i < ns->Count; ++i) {
        GP_API_SET_ENTRY *entry = (GP_API_SET_ENTRY *)(map + ns->EntryOffset) + i;
        GP_API_SET_VALUE *fallback = NULL;
        if ((entry->NameLength & 1) || (entry->HashedLength & 1) ||
            !gp_range(ns->Size, entry->NameOffset, entry->NameLength, 1) ||
            !gp_api_set_equal(name, length, (WCHAR *)(map + entry->NameOffset),
                              entry->NameLength / sizeof(WCHAR),
                              entry->HashedLength / sizeof(WCHAR)))
            continue;
        if (!gp_range(ns->Size, entry->ValueOffset, entry->ValueCount,
                      sizeof(GP_API_SET_VALUE)))
            return NULL;
        for (j = 0; j < entry->ValueCount; ++j) {
            GP_API_SET_VALUE *value = (GP_API_SET_VALUE *)(map + entry->ValueOffset) + j;
            if ((value->NameLength & 1) || (value->ValueLength & 1) ||
                !gp_range(ns->Size, value->NameOffset, value->NameLength, 1) ||
                !gp_range(ns->Size, value->ValueOffset, value->ValueLength, 1))
                return NULL;
            if (value->NameLength == 0) {
                fallback = value;
            } else if (importer_name && importer_name->Buffer &&
                       gp_wide_equal(importer_name->Buffer,
                                     importer_name->Length / sizeof(WCHAR),
                                     (WCHAR *)(map + value->NameOffset),
                                     value->NameLength / sizeof(WCHAR))) {
                return gp_find_wide_module((WCHAR *)(map + value->ValueOffset),
                                           value->ValueLength / sizeof(WCHAR));
            }
        }
        return fallback ? gp_find_wide_module((WCHAR *)(map + fallback->ValueOffset),
                                               fallback->ValueLength / sizeof(WCHAR)) : NULL;
    }
    return NULL;
}

static FARPROC gp_resolve(BYTE *module, const char *name, SIZE_T name_length,
                          DWORD ordinal, int by_ordinal, unsigned int depth)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_EXPORT_DIRECTORY *exports;
    IMAGE_DATA_DIRECTORY directory;
    DWORD image_size, rva, index, i;
    DWORD *functions, *names;
    WORD *ordinals;

    if (!module || depth >= 32)
        return NULL;
    dos = (IMAGE_DOS_HEADER *)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
        return NULL;
    nt = (IMAGE_NT_HEADERS *)(module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return NULL;
    image_size = nt->OptionalHeader.SizeOfImage;
    directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!directory.VirtualAddress || directory.Size < sizeof(*exports) ||
        !gp_range(image_size, directory.VirtualAddress, directory.Size, 1))
        return NULL;
    exports = (IMAGE_EXPORT_DIRECTORY *)(module + directory.VirtualAddress);
    if (!gp_range(image_size, exports->AddressOfFunctions, exports->NumberOfFunctions, sizeof(DWORD)) ||
        !gp_range(image_size, exports->AddressOfNames, exports->NumberOfNames, sizeof(DWORD)) ||
        !gp_range(image_size, exports->AddressOfNameOrdinals, exports->NumberOfNames, sizeof(WORD)))
        return NULL;
    functions = (DWORD *)(module + exports->AddressOfFunctions);
    names = (DWORD *)(module + exports->AddressOfNames);
    ordinals = (WORD *)(module + exports->AddressOfNameOrdinals);

    if (by_ordinal) {
        if (ordinal < exports->Base || ordinal - exports->Base >= exports->NumberOfFunctions)
            return NULL;
        index = ordinal - exports->Base;
    } else {
        index = exports->NumberOfFunctions;
        for (i = 0; i < exports->NumberOfNames; ++i) {
            SIZE_T j;
            if (!gp_range(image_size, names[i], name_length + 1, 1))
                continue;
            for (j = 0; j < name_length; ++j)
                if (module[names[i] + j] != (BYTE)name[j])
                    break;
            if (j == name_length && module[names[i] + j] == 0) {
                index = ordinals[i];
                break;
            }
        }
        if (index >= exports->NumberOfFunctions)
            return NULL;
    }

    rva = functions[index];
    if (!rva || rva >= image_size)
        return NULL;
    if (rva >= directory.VirtualAddress &&
        rva - directory.VirtualAddress < directory.Size) {
        const char *forward = (const char *)(module + rva);
        SIZE_T remaining = directory.Size - (rva - directory.VirtualAddress);
        SIZE_T dot = 0, end, j;
        BYTE *target;
        DWORD target_ordinal = 0;
        while (dot < remaining && forward[dot] && forward[dot] != '.')
            ++dot;
        if (dot == 0 || dot == remaining || forward[dot] != '.')
            return NULL;
        end = dot + 1;
        while (end < remaining && forward[end])
            ++end;
        if (end == remaining || end == dot + 1)
            return NULL;
        target = gp_find_module(forward, dot);
        if (!target)
            target = gp_api_set_module(forward, dot, module);
        if (!target)
            return NULL;
        if (forward[dot + 1] != '#')
            return gp_resolve(target, forward + dot + 1, end - dot - 1, 0, 0, depth + 1);
        if (end == dot + 2)
            return NULL;
        for (j = dot + 2; j < end; ++j) {
            unsigned int digit = (unsigned char)forward[j] - '0';
            if (digit > 9 || target_ordinal > (MAXDWORD - digit) / 10)
                return NULL;
            target_ordinal = target_ordinal * 10 + digit;
        }
        return gp_resolve(target, NULL, 0, target_ordinal, 1, depth + 1);
    }
    return (FARPROC)(module + rva);
}

FARPROC GetProcAddressPtr(LPCSTR name)
{
    LIST_ENTRY *head, *link;
    SIZE_T length = 0;
    if (!name || !*name)
        return NULL;
    while (name[length])
        ++length;
    head = gp_loader_list();
    if (!head)
        return NULL;
    for (link = head->Flink; link != head; link = link->Flink) {
        BYTE *entry = gp_entry(link);
        FARPROC result = gp_resolve(*(BYTE **)(entry + ENTRY_BASE_OFFSET),
                                    name, length, 0, 0, 0);
        if (result)
            return result;
    }
    return NULL;
}
