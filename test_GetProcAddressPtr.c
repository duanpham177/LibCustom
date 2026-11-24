#include <windows.h>
#include <stdio.h>

/*
 * From an MSVC developer command prompt:
 * cl /W4 /WX /O2 /Gy- /GS- test_GetProcAddressPtr.c GetProcAddressPtr.c
 *
 * Windows APIs and the C runtime are used here for testing only.
 */
FARPROC GetProcAddressPtr(LPCSTR name);

int main(void)
{
    const char *names[] = {
        "Sleep",
        "CreateFileW",
        "GetCurrentProcessId",
        "GetSystemTimePreciseAsFileTime"
    };
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    SIZE_T i;
    int failures = 0;
    typedef DWORD (WINAPI *GetCurrentProcessIdFn)(void);
    GetCurrentProcessIdFn get_pid;

    if (!kernel32) {
        puts("FAIL: kernel32.dll is not loaded");
        return 1;
    }

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        FARPROC expected = GetProcAddress(kernel32, names[i]);
        FARPROC actual = GetProcAddressPtr(names[i]);
        if (!expected || actual != expected) {
            printf("FAIL: %s\n", names[i]);
            ++failures;
        } else {
            printf("PASS: %s\n", names[i]);
        }
    }

    get_pid = (GetCurrentProcessIdFn)GetProcAddressPtr("GetCurrentProcessId");
    if (!get_pid || get_pid() != GetCurrentProcessId()) {
        puts("FAIL: calling GetCurrentProcessId through the resolved pointer");
        ++failures;
    } else {
        puts("PASS: calling GetCurrentProcessId through the resolved pointer");
    }

    if (GetProcAddressPtr(NULL) || GetProcAddressPtr("") ||
        GetProcAddressPtr("ThisExportDoesNotExist_843067") ||
        GetProcAddressPtr("sleep")) {
        puts("FAIL: invalid or case-sensitive names");
        ++failures;
    } else {
        puts("PASS: invalid or case-sensitive names");
    }

    return failures ? 1 : 0;
}
