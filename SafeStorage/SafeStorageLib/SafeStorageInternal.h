#ifndef _SAFE_STORAGE_INTERNAL_H_
#define _SAFE_STORAGE_INTERNAL_H_

#include "includes.h"

EXTERN_C_START;

#define MIN_USERNAME_LENGTH     5
#define MAX_USERNAME_LENGTH     10
#define MIN_PASSWORD_LENGTH     5
#define MAX_PASSWORD_LENGTH     128
#define HASH_STRING_LENGTH      64
#define MAX_USERS_DIR_PATH      MAX_PATH
#define MAX_USER_DIR_PATH       MAX_PATH
#define USERS_SUBDIR            "Users"
#define USERS_FILE              "users.txt"
#define MAX_LOGIN_ATTEMPTS      5
#define LOGIN_ATTEMPT_WINDOW    1

typedef struct _GLOBAL_STATE {
    CRITICAL_SECTION Lock;
    BOOL IsInitialized;
    BOOL IsUserLoggedIn;
    CHAR CurrentUsername[MAX_USERNAME_LENGTH + 1];
    CHAR AppDirectory[MAX_PATH];
    CHAR UsersDirectory[MAX_PATH];
    CHAR UsersFilePath[MAX_PATH];
    
    ULONGLONG LoginAttempts[MAX_LOGIN_ATTEMPTS];
    DWORD LoginAttemptIndex;
} GLOBAL_STATE, *PGLOBAL_STATE;

extern GLOBAL_STATE g_State;

_Must_inspect_result_
BOOL
ValidateUsername(
    _In_reads_(Length) const char* Username,
    _In_range_(5, 10) uint16_t Length
);

_Must_inspect_result_
BOOL
ValidatePassword(
    _In_reads_(Length) const char* Password,
    _In_range_(5, 128) uint16_t Length
);

_Must_inspect_result_
NTSTATUS
HashPassword(
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength,
    _Out_writes_z_(HASH_STRING_LENGTH + 1) char* HashOutput
);

_Must_inspect_result_
BOOL
UserExists(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
);

_Must_inspect_result_
BOOL
VerifyCredentials(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength
);

_Must_inspect_result_
BOOL
VerifyCredentialsWithSalt(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _In_reads_(PasswordLength) const char* Password,
    _In_ uint16_t PasswordLength
);

_Must_inspect_result_
NTSTATUS
AddUserToFileWithSalt(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _In_reads_bytes_(SALT_LENGTH) const BYTE* Salt,
    _In_reads_z_(HASH_STRING_LENGTH + 1) const char* PasswordHash
);

_Must_inspect_result_
NTSTATUS
CreateUserDirectory(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength
);

_Must_inspect_result_
BOOL
CheckBruteForceProtection(
    VOID
);

VOID
RecordLoginAttempt(
    VOID
);

_Must_inspect_result_
BOOL
SanitizeString(
    _In_reads_(Length) const char* Input,
    _In_ uint16_t Length,
    _In_ uint16_t MaxLength
);

_Must_inspect_result_
NTSTATUS
GetUserDirectoryPath(
    _In_reads_(UsernameLength) const char* Username,
    _In_ uint16_t UsernameLength,
    _Out_writes_z_(MAX_PATH) char* PathBuffer
);

_Must_inspect_result_
NTSTATUS
CopyFileWithThreadPool(
    _In_z_ const char* SourcePath,
    _In_z_ const char* DestinationPath
);

_Must_inspect_result_
BOOL
ValidatePathBelongsToCurrentUser(
    _In_z_ const char* Path
);

_Must_inspect_result_
BOOL
ValidatePathNotInOtherUserDirectory(
    _In_z_ const char* Path
);

EXTERN_C_END;

#endif // _SAFE_STORAGE_INTERNAL_H_