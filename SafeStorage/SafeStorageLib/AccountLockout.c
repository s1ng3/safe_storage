#include "SafeStorageInternal.h"
#include "AccountLockout.h"
#include <string.h>

typedef struct _LOCKOUT_ENTRY {
    CHAR Username[MAX_USERNAME_LENGTH + 1];
    DWORD FailedAttempts;
    ULONGLONG LockoutUntil;
    BOOL IsActive;
} LOCKOUT_ENTRY, *PLOCKOUT_ENTRY;

static LOCKOUT_ENTRY g_LockoutTable[MAX_TRACKED_ACCOUNTS];
static CRITICAL_SECTION g_LockoutLock;
static BOOL g_LockoutInitialized = FALSE;


_Must_inspect_result_
NTSTATUS
InitializeAccountLockout(
    VOID
)
{
    if (g_LockoutInitialized)
    {
        return STATUS_SUCCESS;
    }

    if (!InitializeCriticalSectionAndSpinCount(&g_LockoutLock, 0x00000400))
    {
        return STATUS_UNSUCCESSFUL;
    }

    SecureZeroMemory(g_LockoutTable, sizeof(g_LockoutTable));

    g_LockoutInitialized = TRUE;
    return STATUS_SUCCESS;
}


VOID
CleanupAccountLockout(
    VOID
)
{
    if (!g_LockoutInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_LockoutLock);

    SecureZeroMemory(g_LockoutTable, sizeof(g_LockoutTable));
    g_LockoutInitialized = FALSE;

    LeaveCriticalSection(&g_LockoutLock);
    DeleteCriticalSection(&g_LockoutLock);
}


static PLOCKOUT_ENTRY
FindOrCreateLockoutEntry(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
)
{
    PLOCKOUT_ENTRY entry = NULL;
    PLOCKOUT_ENTRY emptySlot = NULL;

    for (DWORD i = 0; i < MAX_TRACKED_ACCOUNTS; i++)
    {
        if (g_LockoutTable[i].IsActive &&
            strncmp(g_LockoutTable[i].Username, Username, UsernameLength) == 0 &&
            g_LockoutTable[i].Username[UsernameLength] == '\0')
        {
            return &g_LockoutTable[i];
        }

        if (!g_LockoutTable[i].IsActive && emptySlot == NULL)
        {
            emptySlot = &g_LockoutTable[i];
        }
    }

    if (emptySlot != NULL)
    {
        SecureZeroMemory(emptySlot, sizeof(LOCKOUT_ENTRY));
        memcpy(emptySlot->Username, Username, UsernameLength);
        emptySlot->Username[UsernameLength] = '\0';
        emptySlot->IsActive = TRUE;
        entry = emptySlot;
    }

    return entry;
}


_Must_inspect_result_
BOOL
IsAccountLocked(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
)
{
    BOOL isLocked = FALSE;
    ULONGLONG currentTime;
    PLOCKOUT_ENTRY entry;

    if (!g_LockoutInitialized)
    {
        return FALSE;
    }

    if (Username == NULL || UsernameLength == 0)
    {
        return FALSE;
    }

    EnterCriticalSection(&g_LockoutLock);

    currentTime = GetTickCount64();
    entry = FindOrCreateLockoutEntry(Username, UsernameLength);

    if (entry != NULL && entry->LockoutUntil > 0)
    {
        if (currentTime < entry->LockoutUntil)
        {
            ULONGLONG remainingMs = entry->LockoutUntil - currentTime;
            ULONGLONG remainingSec = remainingMs / 1000;

            printf("Account '%.*s' is locked. Try again in %llu seconds.\n",
                   (int)UsernameLength, Username, remainingSec);

            isLocked = TRUE;
        }
        else
        {
            entry->FailedAttempts = 0;
            entry->LockoutUntil = 0;
            printf("Lockout for account '%.*s' has expired.\n",
                   (int)UsernameLength, Username);
        }
    }

    LeaveCriticalSection(&g_LockoutLock);

    return isLocked;
}


VOID
RecordFailedLoginAttempt(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
)
{
    ULONGLONG currentTime;
    PLOCKOUT_ENTRY entry;

    if (!g_LockoutInitialized)
    {
        return;
    }

    if (Username == NULL || UsernameLength == 0)
    {
        return;
    }

    EnterCriticalSection(&g_LockoutLock);

    currentTime = GetTickCount64();
    entry = FindOrCreateLockoutEntry(Username, UsernameLength);

    if (entry != NULL)
    {
        entry->FailedAttempts++;

        printf("Failed login attempt #%lu for account '%.*s'.\n",
               entry->FailedAttempts, (int)UsernameLength, Username);

        if (entry->FailedAttempts >= MAX_FAILED_ATTEMPTS)
        {
            entry->LockoutUntil = currentTime + (LOCKOUT_DURATION_SECONDS * 1000);

            printf("Account '%.*s' locked due to %d failed login attempts.\n",
                   (int)UsernameLength, Username, MAX_FAILED_ATTEMPTS);
            printf("Account will be unlocked in %d seconds.\n",
                   LOCKOUT_DURATION_SECONDS);
        }
    }
    else
    {
        printf("Failed to track login attempt - lockout table full.\n");
    }

    LeaveCriticalSection(&g_LockoutLock);
}


VOID
ResetFailedAttempts(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
)
{
    PLOCKOUT_ENTRY entry;

    if (!g_LockoutInitialized)
    {
        return;
    }

    if (Username == NULL || UsernameLength == 0)
    {
        return;
    }

    EnterCriticalSection(&g_LockoutLock);

    entry = FindOrCreateLockoutEntry(Username, UsernameLength);

    if (entry != NULL)
    {
        if (entry->FailedAttempts > 0)
        {
            printf("Resetting %lu failed attempts for account '%.*s'.\n",
                   entry->FailedAttempts, (int)UsernameLength, Username);
        }

        entry->FailedAttempts = 0;
        entry->LockoutUntil = 0;
    }

    LeaveCriticalSection(&g_LockoutLock);
}