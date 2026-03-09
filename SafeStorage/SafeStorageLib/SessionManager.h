#ifndef _SESSION_MANAGER_H_
#define _SESSION_MANAGER_H_

#include "includes.h"

EXTERN_C_START;

#define SESSION_TIMEOUT_SECONDS 300  // 5 minutes

_Must_inspect_result_
NTSTATUS
InitializeSessionManager();

VOID
CleanupSessionManager();

VOID
UpdateSessionActivity();

_Must_inspect_result_
BOOL
IsSessionExpired();

VOID
ExpireSession();

_Must_inspect_result_
DWORD
GetSessionTimeRemaining();

VOID
ResetSession();

EXTERN_C_END;

#endif // _SESSION_MANAGER_H_
