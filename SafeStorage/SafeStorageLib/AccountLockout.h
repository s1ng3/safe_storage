#ifndef _ACCOUNT_LOCKOUT_H_
#define _ACCOUNT_LOCKOUT_H_

#include "includes.h"

EXTERN_C_START;

#define MAX_FAILED_ATTEMPTS 5
#define LOCKOUT_DURATION_SECONDS 300  // 5 minutes
#define MAX_TRACKED_ACCOUNTS 20

_Must_inspect_result_
NTSTATUS
InitializeAccountLockout(
    VOID
);

VOID
CleanupAccountLockout(
    VOID
);

_Must_inspect_result_
BOOL
IsAccountLocked(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
);

VOID
RecordFailedLoginAttempt(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
);

VOID
ResetFailedAttempts(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
);

EXTERN_C_END;

#endif // _ACCOUNT_LOCKOUT_H_
