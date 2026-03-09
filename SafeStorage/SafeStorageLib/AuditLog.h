#ifndef _AUDIT_LOG_H_
#define _AUDIT_LOG_H_

#include "includes.h"

EXTERN_C_START;

typedef enum _SAFESTORAGE_AUDIT_EVENT_TYPE {
    AUDIT_SYSTEM_INIT = 0,
    AUDIT_SYSTEM_DEINIT,
    AUDIT_USER_REGISTER,
    AUDIT_LOGIN_SUCCESS,
    AUDIT_LOGIN_FAILED,
    AUDIT_LOGIN_LOCKED,
    AUDIT_USER_LOGOUT,
    AUDIT_FILE_STORE,
    AUDIT_FILE_RETRIEVE,
    AUDIT_SESSION_TIMEOUT,
    AUDIT_ERROR,
    AUDIT_SECURITY_VIOLATION
} SAFESTORAGE_AUDIT_EVENT_TYPE;

_Must_inspect_result_
NTSTATUS
InitializeAuditLog(
    _In_z_ const char* AuditLogPath
);

VOID
CloseAuditLog(
    VOID
);

_Must_inspect_result_
NTSTATUS
LogAuditEvent(
    _In_ SAFESTORAGE_AUDIT_EVENT_TYPE EventType,
    _In_opt_z_ const char* Username,
    _In_opt_z_ const char* Details,
    _In_ NTSTATUS Status
);

_Must_inspect_result_
NTSTATUS
LogAuditEventFormatted(
    _In_ SAFESTORAGE_AUDIT_EVENT_TYPE EventType,
    _In_opt_z_ const char* Username,
    _In_ NTSTATUS Status,
    _In_z_ _Printf_format_string_ const char* Format,
    ...
);

EXTERN_C_END;

#endif // _AUDIT_LOG_H_
