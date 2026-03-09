#include "SafeStorageInternal.h"
#include "PasswordSecurity.h"
#include <string.h>

GLOBAL_STATE g_State = { 0 };


_Must_inspect_result_
BOOL
ValidateUsername(
    _In_reads_(Length) const char* Username,
    _In_range_(5, 10) uint16_t Length
)
{
    if (Length < MIN_USERNAME_LENGTH || Length > MAX_USERNAME_LENGTH)
    {
        return FALSE;
    }

    if (Username[Length] != '\0')
    {
        return FALSE;
    }

    for (uint16_t i = 0; i < Length; i++)
    {
        char c = Username[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
        {
            return FALSE;
        }
    }

    return TRUE;
}


_Must_inspect_result_
BOOL
ValidatePassword(
    _In_reads_(Length) const char* Password,
    _In_range_(5, 128) uint16_t Length
)
{
    BOOL hasDigit = FALSE;
    BOOL hasLower = FALSE;
    BOOL hasUpper = FALSE;
    BOOL hasSpecial = FALSE;
    const char* specialChars = "!@#$%^&";

    if (Length < MIN_PASSWORD_LENGTH)
    {
        return FALSE;
    }

    if (Password[Length] != '\0')
    {
        return FALSE;
    }

    for (uint16_t i = 0; i < Length; i++)
    {
        char c = Password[i];

        if (c >= '0' && c <= '9')
        {
            hasDigit = TRUE;
        }
        else if (c >= 'a' && c <= 'z')
        {
            hasLower = TRUE;
        }
        else if (c >= 'A' && c <= 'Z')
        {
            hasUpper = TRUE;
        }
        else if (strchr(specialChars, c) != NULL)
        {
            hasSpecial = TRUE;
        }
    }

    return hasDigit && hasLower && hasUpper && hasSpecial;
}


_Must_inspect_result_
NTSTATUS
HashPassword(
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength,
    _Out_writes_z_(HASH_STRING_LENGTH + 1) char* HashOutput
)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BYTE hash[32];
    DWORD hashLength = 0;
    DWORD resultLength = 0;

    status = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptGetProperty(
        hAlgorithm,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&hashLength,
        sizeof(DWORD),
        &resultLength,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptCreateHash(
        hAlgorithm,
        &hHash,
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptHashData(
        hHash,
        (PBYTE)Password,
        PasswordLength,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptFinishHash(
        hHash,
        hash,
        sizeof(hash),
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    for (int i = 0; i < 32; i++)
    {
        sprintf_s(&HashOutput[i * 2], 3, "%02x", hash[i]);
    }
    HashOutput[HASH_STRING_LENGTH] = '\0';

Cleanup:
    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (hAlgorithm)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    SecureZeroMemory(hash, sizeof(hash));

    return status;
}


_Must_inspect_result_
BOOL
UserExists(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
)
{
    FILE* file = NULL;
    BOOL exists = FALSE;
    char line[512];
    char storedUsername[MAX_USERNAME_LENGTH + 1];
    errno_t err;

    errno_t fileErr = fopen_s(&file, g_State.UsersFilePath, "r");
    if (fileErr != 0 || file == NULL)
    {
        return FALSE;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* separator = strchr(line, ':');
        if (separator != NULL)
        {
            size_t usernameLen = separator - line;
            if (usernameLen == UsernameLength && usernameLen <= MAX_USERNAME_LENGTH)
            {
                err = memcpy_s(storedUsername, sizeof(storedUsername), line, usernameLen);
                if (err != 0)
                {
                    printf("Memory copy error in UserExists.\n");
                    continue;
                }
                storedUsername[usernameLen] = '\0';

                if (strncmp(storedUsername, Username, UsernameLength) == 0)
                {
                    exists = TRUE;
                    break;
                }
            }
        }
    }

    fclose(file);
    SecureZeroMemory(line, sizeof(line));
    SecureZeroMemory(storedUsername, sizeof(storedUsername));

    return exists;
}


_Must_inspect_result_
BOOL
VerifyCredentials(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength
)
{
    FILE* file = NULL;
    BOOL verified = FALSE;
    char line[512];
    char storedUsername[MAX_USERNAME_LENGTH + 1];
    char storedHash[HASH_STRING_LENGTH + 1];
    char computedHash[HASH_STRING_LENGTH + 1];
    NTSTATUS status;
    errno_t err;

    status = HashPassword(Password, PasswordLength, computedHash);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    errno_t fileErr = fopen_s(&file, g_State.UsersFilePath, "r");
    if (fileErr != 0 || file == NULL)
    {
        goto Cleanup;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* separator = strchr(line, ':');
        if (separator != NULL)
        {
            size_t usernameLen = separator - line;
            if (usernameLen == UsernameLength && usernameLen <= MAX_USERNAME_LENGTH)
            {
                err = memcpy_s(storedUsername, sizeof(storedUsername), line, usernameLen);
                if (err != 0)
                {
                    printf("Memory copy error in VerifyCredentials (username).\n");
                    continue;
                }
                storedUsername[usernameLen] = '\0';

                if (strncmp(storedUsername, Username, UsernameLength) == 0)
                {
                    char* hashStart = separator + 1;
                    char* newline = strchr(hashStart, '\n');
                    if (newline != NULL)
                    {
                        *newline = '\0';
                    }

                    size_t hashLen = strlen(hashStart);
                    if (hashLen == HASH_STRING_LENGTH)
                    {
                        err = memcpy_s(storedHash, sizeof(storedHash), hashStart, HASH_STRING_LENGTH);
                        if (err != 0)
                        {
                            printf("Memory copy error in VerifyCredentials (hash).\n");
                            break;
                        }
                        storedHash[HASH_STRING_LENGTH] = '\0';

                        if (strncmp(storedHash, computedHash, HASH_STRING_LENGTH) == 0)
                        {
                            verified = TRUE;
                        }
                    }
                    break;
                }
            }
        }
    }

Cleanup:
    if (file)
    {
        fclose(file);
    }

    SecureZeroMemory(line, sizeof(line));
    SecureZeroMemory(storedUsername, sizeof(storedUsername));
    SecureZeroMemory(storedHash, sizeof(storedHash));
    SecureZeroMemory(computedHash, sizeof(computedHash));

    return verified;
}


_Must_inspect_result_
NTSTATUS
AddUserToFileWithSalt(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _In_reads_bytes_(SALT_LENGTH) const BYTE* Salt,
    _In_reads_z_(HASH_STRING_LENGTH + 1) const char* PasswordHash
)
{
    FILE* file = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    char saltHex[SALT_LENGTH * 2 + 1];

    for (int i = 0; i < SALT_LENGTH; i++)
    {
        sprintf_s(&saltHex[i * 2], 3, "%02x", Salt[i]);
    }
    saltHex[SALT_LENGTH * 2] = '\0';

    errno_t err = fopen_s(&file, g_State.UsersFilePath, "a");
    if (err != 0 || file == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    fprintf(file, "%.*s:%s:%s\n", (int)UsernameLength, Username, saltHex, PasswordHash);

    fclose(file);
    SecureZeroMemory(saltHex, sizeof(saltHex));
    return status;
}


_Must_inspect_result_
BOOL
VerifyCredentialsWithSalt(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength
)
{
    FILE* file = NULL;
    BOOL verified = FALSE;
    char line[1024];
    char storedUsername[MAX_USERNAME_LENGTH + 1];
    char storedSaltHex[SALT_LENGTH * 2 + 1];
    char storedHash[HASH_STRING_LENGTH + 1];
    char computedHash[HASH_STRING_LENGTH + 1];
    BYTE salt[SALT_LENGTH];
    NTSTATUS status;
    errno_t err;

    errno_t fileErr = fopen_s(&file, g_State.UsersFilePath, "r");
    if (fileErr != 0 || file == NULL)
    {
        goto Cleanup;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* firstColon = strchr(line, ':');
        if (firstColon == NULL)
        {
            continue;
        }

        size_t usernameLen = firstColon - line;
        if (usernameLen != UsernameLength || usernameLen > MAX_USERNAME_LENGTH)
        {
            continue;
        }

        err = memcpy_s(storedUsername, sizeof(storedUsername), line, usernameLen);
        if (err != 0)
        {
            printf("Memory copy error in VerifyCredentialsWithSalt (username).\n");
            continue;
        }
        storedUsername[usernameLen] = '\0';

        if (strncmp(storedUsername, Username, UsernameLength) != 0)
        {
            continue;
        }

        char* secondColon = strchr(firstColon + 1, ':');
        
        if (secondColon != NULL)
        {
            size_t saltLen = secondColon - (firstColon + 1);
            if (saltLen != SALT_LENGTH * 2)
            {
                continue;
            }

            err = memcpy_s(storedSaltHex, sizeof(storedSaltHex), firstColon + 1, saltLen);
            if (err != 0)
            {
                printf("Memory copy error in VerifyCredentialsWithSalt (salt).\n");
                continue;
            }
            storedSaltHex[saltLen] = '\0';

            for (int i = 0; i < SALT_LENGTH; i++)
            {
                sscanf_s(&storedSaltHex[i * 2], "%2hhx", &salt[i]);
            }

            char* hashStart = secondColon + 1;
            char* newline = strchr(hashStart, '\n');
            if (newline != NULL)
            {
                *newline = '\0';
            }

            size_t hashLen = strlen(hashStart);
            if (hashLen != HASH_STRING_LENGTH)
            {
                continue;
            }

            err = memcpy_s(storedHash, sizeof(storedHash), hashStart, HASH_STRING_LENGTH);
            if (err != 0)
            {
                printf("Memory copy error in VerifyCredentialsWithSalt (hash).\n");
                continue;
            }
            storedHash[HASH_STRING_LENGTH] = '\0';

            status = HashPasswordWithSalt(Password, PasswordLength, salt, computedHash);
            if (!NT_SUCCESS(status))
            {
                continue;
            }

            if (strncmp(storedHash, computedHash, HASH_STRING_LENGTH) == 0)
            {
                verified = TRUE;
            }
        }
        else
        {
            char* hashStart = firstColon + 1;
            char* newline = strchr(hashStart, '\n');
            if (newline != NULL)
            {
                *newline = '\0';
            }

            size_t hashLen = strlen(hashStart);
            if (hashLen == HASH_STRING_LENGTH)
            {
                err = memcpy_s(storedHash, sizeof(storedHash), hashStart, HASH_STRING_LENGTH);
                if (err != 0)
                {
                    printf("Memory copy error in VerifyCredentialsWithSalt (legacy hash).\n");
                    continue;
                }
                storedHash[HASH_STRING_LENGTH] = '\0';

                char legacyHash[HASH_STRING_LENGTH + 1];
                status = HashPassword(Password, PasswordLength, legacyHash);
                if (NT_SUCCESS(status))
                {
                    if (strncmp(storedHash, legacyHash, HASH_STRING_LENGTH) == 0)
                    {
                        verified = TRUE;
                    }
                    SecureZeroMemory(legacyHash, sizeof(legacyHash));
                }
            }
        }
        break;
    }

Cleanup:
    if (file)
    {
        fclose(file);
    }

    SecureZeroMemory(line, sizeof(line));
    SecureZeroMemory(storedUsername, sizeof(storedUsername));
    SecureZeroMemory(storedSaltHex, sizeof(storedSaltHex));
    SecureZeroMemory(storedHash, sizeof(storedHash));
    SecureZeroMemory(computedHash, sizeof(computedHash));
    SecureZeroMemory(salt, sizeof(salt));

    return verified;
}


_Must_inspect_result_
NTSTATUS
CreateUserDirectory(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
)
{
    char userDirPath[MAX_PATH];
    HRESULT hr;

    hr = StringCchPrintfA(
        userDirPath,
        MAX_PATH,
        "%s\\%.*s",
        g_State.UsersDirectory,
        (int)UsernameLength,
        Username
    );

    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (!CreateDirectoryA(userDirPath, NULL))
    {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}


_Must_inspect_result_
BOOL
CheckBruteForceProtection(
    VOID
)
{
    ULONGLONG currentTime = GetTickCount64();
    DWORD recentAttempts = 0;

    for (DWORD i = 0; i < MAX_LOGIN_ATTEMPTS; i++)
    {
        if (g_State.LoginAttempts[i] != 0)
        {
            ULONGLONG timeDiff = currentTime - g_State.LoginAttempts[i];
            if (timeDiff < (LOGIN_ATTEMPT_WINDOW * 1000))
            {
                recentAttempts++;
            }
        }
    }

    return recentAttempts >= MAX_LOGIN_ATTEMPTS;
}


VOID
RecordLoginAttempt(
    VOID
)
{
    DWORD64 currentTime = GetTickCount64();
    
    g_State.LoginAttempts[g_State.LoginAttemptIndex] = currentTime;
    g_State.LoginAttemptIndex = (g_State.LoginAttemptIndex + 1) % MAX_LOGIN_ATTEMPTS;
}


_Must_inspect_result_
BOOL
SanitizeString(
    _In_reads_(Length) const char* Input,
    _In_ uint16_t Length,
    _In_ uint16_t MaxLength
)
{
    if (Input == NULL || Length > MaxLength)
    {
        return FALSE;
    }

    if (Input[Length] != '\0')
    {
        return FALSE;
    }

    if (strstr(Input, "..") != NULL)
    {
        return FALSE;
    }

    for (uint16_t i = 0; i < Length; i++)
    {
        char c = Input[i];
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || 
              c == '\\' || c == '/' || c == ':' ||
              c == ' ' || c == '@' || c == '#' ||
              c == '$' || c == '%' || c == '^' ||
              c == '&' || c == '!'))
        {
            return FALSE;
        }
    }

    return TRUE;
}


_Must_inspect_result_
NTSTATUS
GetUserDirectoryPath(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _Out_writes_z_(MAX_PATH) char* PathBuffer
)
{
    HRESULT hr;
    
    if (g_State.IsUserLoggedIn)
    {
        size_t currentUsernameLen = strlen(g_State.CurrentUsername);
        
        if (currentUsernameLen != UsernameLength ||
            strncmp(g_State.CurrentUsername, Username, UsernameLength) != 0)
        {
            printf("Username mismatch.\n");
            printf("Logged-in user: %s\n", g_State.CurrentUsername);
            printf("Requested user: %.*s\n", (int)UsernameLength, Username);
            return STATUS_ACCESS_DENIED;
        }
    }

    hr = StringCchPrintfA(
        PathBuffer,
        MAX_PATH,
        "%s\\%.*s",
        g_State.UsersDirectory,
        (int)UsernameLength,
        Username
    );

    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


_Must_inspect_result_
BOOL
ValidatePathBelongsToCurrentUser(
    _In_z_ const char* Path
)
{
    char expectedUserDir[MAX_PATH];
    char canonicalPath[MAX_PATH];
    char canonicalUserDir[MAX_PATH];
    HRESULT hr;
    DWORD result;
    size_t userDirLen;

    if (Path == NULL)
    {
        return FALSE;
    }

    result = GetFullPathNameA(Path, MAX_PATH, canonicalPath, NULL);
    if (result == 0 || result >= MAX_PATH)
    {
        printf("Failed to get canonical path.\n");
        return FALSE;
    }

    hr = StringCchPrintfA(
        expectedUserDir,
        MAX_PATH,
        "%s\\%s",
        g_State.UsersDirectory,
        g_State.CurrentUsername
    );

    if (FAILED(hr))
    {
        return FALSE;
    }

    result = GetFullPathNameA(expectedUserDir, MAX_PATH, canonicalUserDir, NULL);
    if (result == 0 || result >= MAX_PATH)
    {
        printf("Failed to get canonical user directory path.\n");
        return FALSE;
    }

    userDirLen = strlen(canonicalUserDir);

    if (_strnicmp(canonicalPath, canonicalUserDir, userDirLen) != 0)
    {
        printf("Security violation: Path does not belong to current user.\n");
        printf("Expected: %s\n", canonicalUserDir);
        printf("Actual: %s\n", canonicalPath);
        return FALSE;
    }

    if (strlen(canonicalPath) > userDirLen)
    {
        char nextChar = canonicalPath[userDirLen];
        if (nextChar != '\\' && nextChar != '/' && nextChar != '\0')
        {
            printf("Security violation: Invalid path structure.\n");
            return FALSE;
        }
    }

    return TRUE;
}

typedef struct _COPY_CONTEXT {
    HANDLE SourceFile;
    HANDLE DestFile;
    LARGE_INTEGER FileSize;
    LONG volatile CompletedChunks;
    LONG volatile TotalChunks;
    LONG volatile HasError;
} COPY_CONTEXT, *PCOPY_CONTEXT;

#define CHUNK_SIZE 4096

typedef struct _CHUNK_WORK {
    PCOPY_CONTEXT Context;
    LARGE_INTEGER Offset;
    DWORD ChunkSize;
} CHUNK_WORK, *PCHUNK_WORK;


VOID CALLBACK
CopyChunkCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Parameter,
    PTP_WORK Work
)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

    PCHUNK_WORK chunkWork = (PCHUNK_WORK)Parameter;
    PCOPY_CONTEXT context = chunkWork->Context;
    BYTE buffer[CHUNK_SIZE];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    OVERLAPPED readOverlapped = { 0 };
    OVERLAPPED writeOverlapped = { 0 };

    if (InterlockedCompareExchange(&context->HasError, 0, 0) != 0)
    {
        free(chunkWork);
        return;
    }

    readOverlapped.Offset = chunkWork->Offset.LowPart;
    readOverlapped.OffsetHigh = chunkWork->Offset.HighPart;
    readOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    writeOverlapped.Offset = chunkWork->Offset.LowPart;
    writeOverlapped.OffsetHigh = chunkWork->Offset.HighPart;
    writeOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (readOverlapped.hEvent == NULL || writeOverlapped.hEvent == NULL)
    {
        InterlockedExchange(&context->HasError, 1);
        goto Cleanup;
    }

    if (!ReadFile(context->SourceFile, buffer, chunkWork->ChunkSize, &bytesRead, &readOverlapped))
    {
        if (GetLastError() == ERROR_IO_PENDING)
        {
            if (!GetOverlappedResult(context->SourceFile, &readOverlapped, &bytesRead, TRUE))
            {
                InterlockedExchange(&context->HasError, 1);
                goto Cleanup;
            }
        }
        else
        {
            InterlockedExchange(&context->HasError, 1);
            goto Cleanup;
        }
    }

    if (!WriteFile(context->DestFile, buffer, bytesRead, &bytesWritten, &writeOverlapped))
    {
        if (GetLastError() == ERROR_IO_PENDING)
        {
            if (!GetOverlappedResult(context->DestFile, &writeOverlapped, &bytesWritten, TRUE))
            {
                InterlockedExchange(&context->HasError, 1);
                goto Cleanup;
            }
        }
        else
        {
            InterlockedExchange(&context->HasError, 1);
            goto Cleanup;
        }
    }

    InterlockedIncrement(&context->CompletedChunks);

Cleanup:
    if (readOverlapped.hEvent)
    {
        CloseHandle(readOverlapped.hEvent);
    }
    if (writeOverlapped.hEvent)
    {
        CloseHandle(writeOverlapped.hEvent);
    }

    SecureZeroMemory(buffer, sizeof(buffer));
    free(chunkWork);
}


_Must_inspect_result_
NTSTATUS
CopyFileWithThreadPool(
    _In_z_ const char* SourcePath,
    _In_z_ const char* DestinationPath
)
{
    HANDLE hSource = INVALID_HANDLE_VALUE;
    HANDLE hDest = INVALID_HANDLE_VALUE;
    NTSTATUS status = STATUS_SUCCESS;
    COPY_CONTEXT context = { 0 };
    PTP_WORK* workItems = NULL;
    LARGE_INTEGER fileSize = { 0 };
    LONG numChunks = 0;

    hSource = CreateFileA(
        SourcePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hSource == INVALID_HANDLE_VALUE)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    if (!GetFileSizeEx(hSource, &fileSize))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    hDest = CreateFileA(
        DestinationPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDest == INVALID_HANDLE_VALUE)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    if (fileSize.QuadPart == 0)
    {
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    numChunks = (LONG)((fileSize.QuadPart + CHUNK_SIZE - 1) / CHUNK_SIZE);

    if (numChunks == 1 || fileSize.QuadPart <= CHUNK_SIZE)
    {
        BYTE buffer[CHUNK_SIZE];
        DWORD bytesRead = 0;
        DWORD bytesWritten = 0;
        OVERLAPPED readOverlapped = { 0 };
        OVERLAPPED writeOverlapped = { 0 };

        readOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        writeOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        if (readOverlapped.hEvent == NULL || writeOverlapped.hEvent == NULL)
        {
            if (readOverlapped.hEvent) CloseHandle(readOverlapped.hEvent);
            if (writeOverlapped.hEvent) CloseHandle(writeOverlapped.hEvent);
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        if (!ReadFile(hSource, buffer, (DWORD)fileSize.QuadPart, &bytesRead, &readOverlapped))
        {
            if (GetLastError() == ERROR_IO_PENDING)
            {
                if (!GetOverlappedResult(hSource, &readOverlapped, &bytesRead, TRUE))
                {
                    CloseHandle(readOverlapped.hEvent);
                    CloseHandle(writeOverlapped.hEvent);
                    status = STATUS_UNSUCCESSFUL;
                    goto Cleanup;
                }
            }
            else
            {
                CloseHandle(readOverlapped.hEvent);
                CloseHandle(writeOverlapped.hEvent);
                status = STATUS_UNSUCCESSFUL;
                goto Cleanup;
            }
        }

        if (!WriteFile(hDest, buffer, bytesRead, &bytesWritten, &writeOverlapped))
        {
            if (GetLastError() == ERROR_IO_PENDING)
            {
                if (!GetOverlappedResult(hDest, &writeOverlapped, &bytesWritten, TRUE))
                {
                    CloseHandle(readOverlapped.hEvent);
                    CloseHandle(writeOverlapped.hEvent);
                    status = STATUS_UNSUCCESSFUL;
                    goto Cleanup;
                }
            }
            else
            {
                CloseHandle(readOverlapped.hEvent);
                CloseHandle(writeOverlapped.hEvent);
                status = STATUS_UNSUCCESSFUL;
                goto Cleanup;
            }
        }

        CloseHandle(readOverlapped.hEvent);
        CloseHandle(writeOverlapped.hEvent);
        SecureZeroMemory(buffer, sizeof(buffer));
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    context.SourceFile = hSource;
    context.DestFile = hDest;
    context.FileSize = fileSize;
    context.TotalChunks = numChunks;
    context.CompletedChunks = 0;
    context.HasError = 0;

    workItems = (PTP_WORK*)calloc(numChunks, sizeof(PTP_WORK));
    if (workItems == NULL)
    {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    for (LONG i = 0; i < numChunks; i++)
    {
        PCHUNK_WORK chunkWork = (PCHUNK_WORK)malloc(sizeof(CHUNK_WORK));
        if (chunkWork == NULL)
        {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }

        chunkWork->Context = &context;
        chunkWork->Offset.QuadPart = (LONGLONG)i * CHUNK_SIZE;
        chunkWork->ChunkSize = (DWORD)min(CHUNK_SIZE, fileSize.QuadPart - chunkWork->Offset.QuadPart);

        workItems[i] = CreateThreadpoolWork(CopyChunkCallback, chunkWork, NULL);
        if (workItems[i] == NULL)
        {
            free(chunkWork);
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        SubmitThreadpoolWork(workItems[i]);
    }

    for (LONG i = 0; i < numChunks; i++)
    {
        if (workItems[i] != NULL)
        {
            WaitForThreadpoolWorkCallbacks(workItems[i], FALSE);
            CloseThreadpoolWork(workItems[i]);
        }
    }

      if (context.HasError != 0)
    {
        status = STATUS_UNSUCCESSFUL;
    }

Cleanup:
    if (workItems)
    {
        free(workItems);
    }

    if (hSource != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hSource);
    }

    if (hDest != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDest);
    }

    return status;
}