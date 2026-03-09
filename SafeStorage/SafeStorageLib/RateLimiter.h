#ifndef _RATE_LIMITER_H_
#define _RATE_LIMITER_H_

#include "includes.h"

EXTERN_C_START;

#define MAX_COMMANDS_PER_MINUTE 30

_Must_inspect_result_
NTSTATUS
InitializeRateLimiter();

VOID
CleanupRateLimiter();

_Must_inspect_result_
BOOL
CheckRateLimit();

VOID
RecordCommand();

_Must_inspect_result_
DWORD
GetRemainingCommandQuota();

VOID
ResetRateLimit();

EXTERN_C_END;

#endif // _RATE_LIMITER_H_
