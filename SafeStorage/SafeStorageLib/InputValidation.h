#ifndef _INPUT_VALIDATION_H_
#define _INPUT_VALIDATION_H_

#include "includes.h"

EXTERN_C_START;

_Must_inspect_result_
BOOL
ValidateInputLength(
    _In_z_ const char* Input,
    _In_ SIZE_T MaxLength,
    _Out_opt_ SIZE_T* ActualLength
);

_Must_inspect_result_
NTSTATUS
SecureReadInput(
    _Out_writes_z_(BufferSize) char* Buffer,
    _In_ SIZE_T BufferSize,
    _Out_ SIZE_T* BytesRead
);

_Must_inspect_result_
BOOL
ValidateCommandInput(
    _In_z_ const char* Command
);

_Must_inspect_result_
BOOL
ValidateArgumentInput(
    _In_z_ const char* Argument
);

_Must_inspect_result_
BOOL
ValidateStringNotEmpty(
    _In_z_ const char* Input
);

_Must_inspect_result_
BOOL
ValidateStringRange(
    _In_z_ const char* Input,
    _In_ SIZE_T MinLength,
    _In_ SIZE_T MaxLength
);

EXTERN_C_END;

#endif // _INPUT_VALIDATION_H_
