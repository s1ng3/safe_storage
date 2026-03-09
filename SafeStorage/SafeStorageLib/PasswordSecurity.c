#include "SafeStorageInternal.h"
#include "PasswordSecurity.h"
#include <string.h>

_Must_inspect_result_
NTSTATUS
GenerateSalt(
    _Out_writes_bytes_(SALT_LENGTH) BYTE* Salt
)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status;

    if (Salt == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptGenRandom(
        hAlgorithm,
        Salt,
        SALT_LENGTH,
        0
    );

    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return status;
}


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
)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status;

    if (Password == NULL || Salt == NULL || DerivedKey == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (PasswordLength == 0 || SaltLength == 0 || KeyLength == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Iterations == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptDeriveKeyPBKDF2(
        hAlgorithm,
        (PBYTE)Password,
        PasswordLength,
        (PBYTE)Salt,
        SaltLength,
        Iterations,
        DerivedKey,
        KeyLength,
        0
    );

    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return status;
}


_Must_inspect_result_
NTSTATUS
HashPasswordWithSalt(
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength,
    _In_reads_bytes_(SALT_LENGTH) const BYTE* Salt,
    _Out_writes_z_(HASH_STRING_LENGTH + 1) char* HashOutput
)
{
    NTSTATUS status;
    BYTE derivedKey[32];

    if (Password == NULL || Salt == NULL || HashOutput == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = DeriveKeyFromPassword(
        Password,
        PasswordLength,
        Salt,
        SALT_LENGTH,
        PBKDF2_ITERATIONS,
        derivedKey,
        sizeof(derivedKey)
    );

    if (!NT_SUCCESS(status))
    {
        SecureZeroMemory(derivedKey, sizeof(derivedKey));
        return status;
    }

    for (int i = 0; i < 32; i++)
    {
        sprintf_s(&HashOutput[i * 2], 3, "%02x", derivedKey[i]);
    }
    HashOutput[HASH_STRING_LENGTH] = '\0';

    SecureZeroMemory(derivedKey, sizeof(derivedKey));

    return STATUS_SUCCESS;
}