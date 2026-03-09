#include "SafeStorageInternal.h"
#include "SessionManager.h"

typedef struct _SESSION_STATE {
    BOOL IsActive;
    ULONGLONG LastActivityTime;
    CHAR Username[MAX_USERNAME_LENGTH + 1];
} SESSION_STATE, *PSESSION_STATE;

static SESSION_STATE g_SessionState;
static CRITICAL_SECTION g_SessionLock;
static BOOL g_SessionInitialized = FALSE;

extern GLOBAL_STATE g_State;


_Must_inspect_result_
NTSTATUS
InitializeSessionManager()
{
    if (g_SessionInitialized)
    {
        return STATUS_SUCCESS;
    }

    if (!InitializeCriticalSectionAndSpinCount(&g_SessionLock, 0x00000400))
    {
        return STATUS_UNSUCCESSFUL;
    }

    SecureZeroMemory(&g_SessionState, sizeof(SESSION_STATE));
    g_SessionState.IsActive = FALSE;
    g_SessionState.LastActivityTime = 0;

    g_SessionInitialized = TRUE;

    return STATUS_SUCCESS;
}


VOID
CleanupSessionManager()
{
    if (!g_SessionInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_SessionLock);

    SecureZeroMemory(&g_SessionState, sizeof(SESSION_STATE));
    g_SessionInitialized = FALSE;

    LeaveCriticalSection(&g_SessionLock);
    DeleteCriticalSection(&g_SessionLock);
}


VOID
UpdateSessionActivity()
{
    if (!g_SessionInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_SessionLock);

    if (g_State.IsUserLoggedIn)
    {
        g_SessionState.IsActive = TRUE;
        g_SessionState.LastActivityTime = GetTickCount64();

        if (g_SessionState.Username[0] == '\0')
        {
            strncpy_s(g_SessionState.Username, sizeof(g_SessionState.Username),
                      g_State.CurrentUsername, _TRUNCATE);
        }
    }

    LeaveCriticalSection(&g_SessionLock);
}


_Must_inspect_result_
BOOL
IsSessionExpired()
{
    BOOL expired = FALSE;
    ULONGLONG currentTime;
    ULONGLONG elapsedSeconds;

    if (!g_SessionInitialized)
    {
        return FALSE;
    }

    if (!g_State.IsUserLoggedIn)
    {
        return FALSE;
    }

    EnterCriticalSection(&g_SessionLock);

    if (g_SessionState.IsActive)
    {
        currentTime = GetTickCount64();
        elapsedSeconds = (currentTime - g_SessionState.LastActivityTime) / 1000;

        if (elapsedSeconds > SESSION_TIMEOUT_SECONDS)
        {
            printf("Session for user '%s' expired after %llu seconds of inactivity.\n",
                   g_SessionState.Username, elapsedSeconds);
            printf("Maximum session timeout is %d seconds.\n", SESSION_TIMEOUT_SECONDS);

            expired = TRUE;
        }
    }

    LeaveCriticalSection(&g_SessionLock);

    return expired;
}


VOID
ExpireSession()
{
    if (!g_SessionInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_SessionLock);

    if (g_SessionState.IsActive)
    {
        printf("Forcing session expiration for user '%s'.\n",
               g_SessionState.Username);

        SecureZeroMemory(g_SessionState.Username, sizeof(g_SessionState.Username));
        g_SessionState.IsActive = FALSE;
        g_SessionState.LastActivityTime = 0;

        EnterCriticalSection(&g_State.Lock);
        SecureZeroMemory(g_State.CurrentUsername, sizeof(g_State.CurrentUsername));
        g_State.IsUserLoggedIn = FALSE;
        LeaveCriticalSection(&g_State.Lock);
    }

    LeaveCriticalSection(&g_SessionLock);
}


_Must_inspect_result_
DWORD
GetSessionTimeRemaining()
{
    DWORD remainingSeconds = 0;
    ULONGLONG currentTime;
    ULONGLONG elapsedSeconds;

    if (!g_SessionInitialized)
    {
        return 0;
    }

    if (!g_State.IsUserLoggedIn || !g_SessionState.IsActive)
    {
        return 0;
    }

    EnterCriticalSection(&g_SessionLock);

    currentTime = GetTickCount64();
    elapsedSeconds = (currentTime - g_SessionState.LastActivityTime) / 1000;

    if (elapsedSeconds < SESSION_TIMEOUT_SECONDS)
    {
        remainingSeconds = (DWORD)(SESSION_TIMEOUT_SECONDS - elapsedSeconds);
    }

    LeaveCriticalSection(&g_SessionLock);

    return remainingSeconds;
}

VOID
ResetSession()
{
    if (!g_SessionInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_SessionLock);

    SecureZeroMemory(&g_SessionState, sizeof(SESSION_STATE));
    g_SessionState.IsActive = FALSE;
    g_SessionState.LastActivityTime = 0;

    LeaveCriticalSection(&g_SessionLock);
}