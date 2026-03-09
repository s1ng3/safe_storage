#ifndef _PASSWORD_SECURITY_H_
#define _PASSWORD_SECURITY_H_

#include "includes.h"

EXTERN_C_START;

#define SALT_LENGTH 16
#define PBKDF2_ITERATIONS 100000

_Must_inspect_result_
NTSTATUS
GenerateSalt(
    _Out_writes_bytes_(SALT_LENGTH) BYTE* Salt
);

_Must_inspect_result_
NTSTATUS
DeriveKeyFromPassword(
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength,
    _In_reads_bytes_(SaltLength) const BYTE* Salt,
    _In_ DWORD SaltLength,
    _In_ DWORD Iterations,
    _Out_writes_bytes_(KeyLength) BYTE* DerivedKey,
    _In_ DWORD KeyLength
);

_Must_inspect_result_
NTSTATUS
HashPasswordWithSalt(
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength,
    _In_reads_bytes_(SALT_LENGTH) const BYTE* Salt,
    _Out_writes_z_(HASH_STRING_LENGTH + 1) char* HashOutput
);

EXTERN_C_END;

#endif // _PASSWORD_SECURITY_H_
