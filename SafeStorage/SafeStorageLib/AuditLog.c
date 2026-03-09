#include "SafeStorageInternal.h"
#include "AuditLog.h"
#include <stdio.h>
#include <stdarg.h>

static FILE* g_AuditLogFile = NULL;
static CRITICAL_SECTION g_AuditLock;
static BOOL g_AuditInitialized = FALSE;
static CHAR g_AuditLogPath[MAX_PATH];

static const char* g_EventTypeNames[] = {
    "SYSTEM_INIT",
    "SYSTEM_DEINIT",
    "USER_REGISTER",
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "LOGIN_LOCKED",
    "USER_LOGOUT",
    "FILE_STORE",
    "FILE_RETRIEVE",
    "SESSION_TIMEOUT",
    "ERROR",
    "SECURITY_VIOLATION"
};


_Must_inspect_result_
NTSTATUS
InitializeAuditLog(
    _In_z_ const char* AuditLogPath
)
{
    errno_t err;

    if (g_AuditInitialized)
    {
        return STATUS_SUCCESS;
    }

    if (AuditLogPath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!InitializeCriticalSectionAndSpinCount(&g_AuditLock, 0x00000400))
    {
        return STATUS_UNSUCCESSFUL;
    }

    strncpy_s(g_AuditLogPath, MAX_PATH, AuditLogPath, _TRUNCATE);

    err = fopen_s(&g_AuditLogFile, g_AuditLogPath, "a");
    if (err != 0 || g_AuditLogFile == NULL)
    {
        DeleteCriticalSection(&g_AuditLock);
        return STATUS_UNSUCCESSFUL;
    }

    setvbuf(g_AuditLogFile, NULL, _IOLBF, BUFSIZ);

    g_AuditInitialized = TRUE;

    LogAuditEvent(AUDIT_SYSTEM_INIT, "SYSTEM", "Audit logging initialized", STATUS_SUCCESS);

    return STATUS_SUCCESS;
}


VOID
CloseAuditLog(
    VOID
)
{
    if (!g_AuditInitialized)
    {
        return;
    }

    EnterCriticalSection(&g_AuditLock);

    if (g_AuditLogFile != NULL)
    {
        LogAuditEvent(AUDIT_SYSTEM_DEINIT, "SYSTEM", "Audit logging closed", STATUS_SUCCESS);

        fclose(g_AuditLogFile);
        g_AuditLogFile = NULL;
    }

    g_AuditInitialized = FALSE;

    LeaveCriticalSection(&g_AuditLock);
    DeleteCriticalSection(&g_AuditLock);
}


_Must_inspect_result_
NTSTATUS
LogAuditEvent(
    _In_ SAFESTORAGE_AUDIT_EVENT_TYPE EventType,
    _In_opt_z_ const char* Username,
    _In_opt_z_ const char* Details,
    _In_ NTSTATUS Status
)
{
    SYSTEMTIME st;
    const char* eventTypeName;

    if (!g_AuditInitialized || g_AuditLogFile == NULL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&g_AuditLock);

    GetLocalTime(&st);

    if (EventType >= 0 && EventType < sizeof(g_EventTypeNames) / sizeof(g_EventTypeNames[0]))
    {
        eventTypeName = g_EventTypeNames[EventType];
    }
    else
    {
        eventTypeName = "UNKNOWN";
    }

    fprintf(g_AuditLogFile,
            "[%04d-%02d-%02d %02d:%02d:%02d] %-20s | User=%-15s | %-50s | Status=0x%08X\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            eventTypeName,
            Username ? Username : "N/A",
            Details ? Details : "N/A",
            Status);

    fflush(g_AuditLogFile);

    LeaveCriticalSection(&g_AuditLock);

    return STATUS_SUCCESS;
}


_Must_inspect_result_
NTSTATUS
LogAuditEventFormatted(
    _In_ SAFESTORAGE_AUDIT_EVENT_TYPE EventType,
    _In_opt_z_ const char* Username,
    _In_ NTSTATUS Status,
    _In_z_ _Printf_format_string_ const char* Format,
    ...
)
{
    char detailsBuffer[512];
    va_list args;
    NTSTATUS result;

    if (Format == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    va_start(args, Format);
    vsnprintf_s(detailsBuffer, sizeof(detailsBuffer), _TRUNCATE, Format, args);
    va_end(args);

    result = LogAuditEvent(EventType, Username, detailsBuffer, Status);

    SecureZeroMemory(detailsBuffer, sizeof(detailsBuffer));

    return result;
}

static const char*
GetStatusString(NTSTATUS Status)
{
    switch (Status)
    {
    case STATUS_SUCCESS:                return "SUCCESS";
    case STATUS_UNSUCCESSFUL:           return "UNSUCCESSFUL";
    case STATUS_INVALID_PARAMETER:      return "INVALID_PARAMETER";
    case STATUS_INVALID_DEVICE_STATE:   return "INVALID_DEVICE_STATE";
    case STATUS_LOGON_FAILURE:          return "LOGON_FAILURE";
    case STATUS_ACCOUNT_LOCKED_OUT:     return "ACCOUNT_LOCKED_OUT";
    case STATUS_NO_SUCH_FILE:           return "NO_SUCH_FILE";
    case STATUS_NO_MEMORY:              return "NO_MEMORY";
    default:                            return "UNKNOWN";
    }
}