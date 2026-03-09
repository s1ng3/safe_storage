#ifndef _FILE_SIZE_LIMITS_H_
#define _FILE_SIZE_LIMITS_H_

#include "includes.h"

EXTERN_C_START;

#define MAX_FILE_SIZE (8ULL * 1024 * 1024 * 1024)  // 8 GB

_Must_inspect_result_
NTSTATUS
GetFileSizeEx64(
    _In_z_ const char* FilePath,
    _Out_ ULONGLONG* FileSize
);

_Must_inspect_result_
BOOL
ValidateFileSize(
    _In_z_ const char* FilePath
);

_Must_inspect_result_
BOOL
CheckFileSizeLimit(
    _In_z_ const char* FilePath,
    _Out_opt_ ULONGLONG* ActualSize
);

VOID
PrintFileSize(
    _In_ ULONGLONG FileSize
);

EXTERN_C_END;

#endif // _FILE_SIZE_LIMITS_H_
