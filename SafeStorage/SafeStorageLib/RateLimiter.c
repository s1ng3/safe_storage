#include "SafeStorageInternal.h"
#include "RateLimiter.h"
#include <string.h>

#define MAX_COMMANDS_PER_MINUTE 30
#define RATE_LIMIT_WINDOW_MS (60 * 1000)

typedef struct _RATE_LIMIT_STATE {
    ULONGLONG CommandTimestamps[MAX_COMMANDS_PER_MINUTE];
    DWORD CommandIndex;
    CRITICAL_SECTION Lock;
    BOOL IsInitialized;
} RATE_LIMIT_STATE, *PRATE_LIMIT_STATE;

static RATE_LIMIT_STATE g_RateLimitState = {0};


_Must_inspect_result_
NTSTATUS
InitializeRateLimiter()
{
    if (g_RateLimitState.IsInitialized)
    {
        return STATUS_SUCCESS;
    }

    if (!InitializeCriticalSectionAndSpinCount(&g_RateLimitState.Lock, 0x00000400))
    {
        return STATUS_UNSUCCESSFUL;
    }

    SecureZeroMemory(g_RateLimitState.CommandTimestamps,
                     sizeof(g_RateLimitState.CommandTimestamps));
    g_RateLimitState.CommandIndex = 0;
    g_RateLimitState.IsInitialized = TRUE;

    printf("Rate limiter initialized (%d commands/minute).\n",
           MAX_COMMANDS_PER_MINUTE);

    return STATUS_SUCCESS;
}


VOID
CleanupRateLimiter()
{
    if (!g_RateLimitState.IsInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_RateLimitState.Lock);

    SecureZeroMemory(g_RateLimitState.CommandTimestamps,
                     sizeof(g_RateLimitState.CommandTimestamps));
    g_RateLimitState.IsInitialized = FALSE;

    LeaveCriticalSection(&g_RateLimitState.Lock);
    DeleteCriticalSection(&g_RateLimitState.Lock);
}


_Must_inspect_result_
BOOL
CheckRateLimit()
{
    ULONGLONG currentTime;
    DWORD recentCommands = 0;
    BOOL allowed;

    if (!g_RateLimitState.IsInitialized)
    {
        return TRUE;
    }

    EnterCriticalSection(&g_RateLimitState.Lock);

    currentTime = GetTickCount64();

    for (DWORD i = 0; i < MAX_COMMANDS_PER_MINUTE; i++)
    {
        if (g_RateLimitState.CommandTimestamps[i] != 0)
        {
            ULONGLONG elapsed = currentTime - g_RateLimitState.CommandTimestamps[i];

            if (elapsed < RATE_LIMIT_WINDOW_MS)
            {
                recentCommands++;
            }
        }
    }

    allowed = (recentCommands < MAX_COMMANDS_PER_MINUTE);

    if (!allowed)
    {
        printf("Rate limit exceeded (%d commands in last minute).\n",
               recentCommands);
        printf("Please wait before executing more commands.\n");
    }

    LeaveCriticalSection(&g_RateLimitState.Lock);

    return allowed;
}


VOID
RecordCommand()
{
    ULONGLONG currentTime;

    if (!g_RateLimitState.IsInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_RateLimitState.Lock);

    currentTime = GetTickCount64();

    g_RateLimitState.CommandTimestamps[g_RateLimitState.CommandIndex] = currentTime;
    g_RateLimitState.CommandIndex = (g_RateLimitState.CommandIndex + 1) % MAX_COMMANDS_PER_MINUTE;

    LeaveCriticalSection(&g_RateLimitState.Lock);
}


_Must_inspect_result_
DWORD
GetRemainingCommandQuota()
{
    ULONGLONG currentTime;
    DWORD recentCommands = 0;
    DWORD remaining;

    if (!g_RateLimitState.IsInitialized)
    {
        return MAX_COMMANDS_PER_MINUTE;
    }

    EnterCriticalSection(&g_RateLimitState.Lock);

    currentTime = GetTickCount64();

    for (DWORD i = 0; i < MAX_COMMANDS_PER_MINUTE; i++)
    {
        if (g_RateLimitState.CommandTimestamps[i] != 0)
        {
            ULONGLONG elapsed = currentTime - g_RateLimitState.CommandTimestamps[i];

            if (elapsed < RATE_LIMIT_WINDOW_MS)
            {
                recentCommands++;
            }
        }
    }

    remaining = (recentCommands < MAX_COMMANDS_PER_MINUTE) ?
                (MAX_COMMANDS_PER_MINUTE - recentCommands) : 0;

    LeaveCriticalSection(&g_RateLimitState.Lock);

    return remaining;
}


VOID
ResetRateLimit()
{
    if (!g_RateLimitState.IsInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_RateLimitState.Lock);

    SecureZeroMemory(g_RateLimitState.CommandTimestamps,
                     sizeof(g_RateLimitState.CommandTimestamps));
    g_RateLimitState.CommandIndex = 0;

    printf("Rate limit counters reset.\n");

    LeaveCriticalSection(&g_RateLimitState.Lock);
}