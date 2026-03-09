#ifndef _PATH_SECURITY_H_
#define _PATH_SECURITY_H_

#include "includes.h"

EXTERN_C_START;

_Must_inspect_result_
NTSTATUS
CanonicalizeAndValidatePath(
    _In_reads_(InputLength) const char* InputPath,
    _In_ SIZE_T InputLength,
    _Out_writes_z_(BufferSize) char* CanonicalPath,
    _In_ SIZE_T BufferSize
);

_Must_inspect_result_
BOOL
ValidateFileExtension(
    _In_reads_(Length) const char* Filename,
    _In_ SIZE_T Length
);

_Must_inspect_result_
BOOL
ValidateNoFormatSpecifiers(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
);

_Must_inspect_result_
BOOL
ValidateNoCommandInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
);

_Must_inspect_result_
BOOL
ValidateNoSQLInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
);

_Must_inspect_result_
BOOL
ValidateNoDelimiterInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
);

_Must_inspect_result_
BOOL
ValidateNoNullInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
);

_Must_inspect_result_
BOOL
ValidatePathSecurity(
    _In_reads_(InputLength) const char* InputPath,
    _In_ SIZE_T InputLength,
    _In_ INT PathType
);

_Must_inspect_result_
BOOL
IsSymlinkOrJunction(
    _In_z_ const char* Path
);

_Must_inspect_result_
BOOL
SanitizePathString(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length,
    _In_ SIZE_T MaxLength
);

EXTERN_C_END;

#endif // _PATH_SECURITY_H_
