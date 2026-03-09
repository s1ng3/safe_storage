#include "Commands.h"
#include "SafeStorageInternal.h"
#include "AccountLockout.h"
#include "AuditLog.h"
#include "SessionManager.h"
#include "RateLimiter.h"
#include "PasswordSecurity.h"
#include "FileIntegrity.h"
#include "FileSizeLimits.h"
#include "PathSecurity.h"

_Must_inspect_result_
NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD result;
    HRESULT hr;
    char auditLogPath[MAX_PATH];

    if (!InitializeCriticalSectionAndSpinCount(&g_State.Lock, 0x00000400))
    {
        return STATUS_UNSUCCESSFUL;
    }

    EnterCriticalSection(&g_State.Lock);

    result = GetCurrentDirectoryA(MAX_PATH, g_State.AppDirectory);
    if (result == 0 || result > MAX_PATH)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    hr = StringCchPrintfA(
        g_State.UsersDirectory,
        MAX_PATH,
        "%s\\%s",
        g_State.AppDirectory,
        USERS_SUBDIR
    );

    if (FAILED(hr))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    hr = StringCchPrintfA(
        g_State.UsersFilePath,
        MAX_PATH,
        "%s\\%s",
        g_State.AppDirectory,
        USERS_FILE
    );

    if (FAILED(hr))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    if (!CreateDirectoryA(g_State.UsersDirectory, NULL))
    {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS)
        {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
    }

    g_State.IsUserLoggedIn = FALSE;
    g_State.IsInitialized = TRUE;
    SecureZeroMemory(g_State.CurrentUsername, sizeof(g_State.CurrentUsername));
    SecureZeroMemory(g_State.LoginAttempts, sizeof(g_State.LoginAttempts));
    g_State.LoginAttemptIndex = 0;

    status = InitializeAccountLockout();
    if (!NT_SUCCESS(status))
    {
        printf("Failed to initialize account lockout system.\n");
    }

    hr = StringCchPrintfA(auditLogPath, MAX_PATH, "%s\\audit.log", g_State.AppDirectory);
    if (SUCCEEDED(hr))
    {
        status = InitializeAuditLog(auditLogPath);
        if (!NT_SUCCESS(status))
        {
            printf("Failed to initialize audit log.\n");
        }
        else
        {
            LogAuditEvent(AUDIT_SYSTEM_INIT, NULL, "SafeStorage system initialized", STATUS_SUCCESS);
        }
    }

    status = InitializeSessionManager();
    if (!NT_SUCCESS(status))
    {
        printf("Failed to initialize session manager.\n");
    }

    status = InitializeRateLimiter();
    if (!NT_SUCCESS(status))
    {
        printf("Failed to initialize rate limiter.\n");
    }

    printf("SafeStorage initialized successfully.\n");
    printf("App Directory: %s\n", g_State.AppDirectory);
    printf("Users Directory: %s\n", g_State.UsersDirectory);
    printf("Security features: Account Lockout, Audit Log, Session Manager, Rate Limiter\n");

    status = STATUS_SUCCESS;

Cleanup:
    LeaveCriticalSection(&g_State.Lock);

    if (!NT_SUCCESS(status))
    {
        DeleteCriticalSection(&g_State.Lock);
    }

    return status;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    if (g_State.IsInitialized)
    {
        EnterCriticalSection(&g_State.Lock);

        LogAuditEvent(AUDIT_SYSTEM_DEINIT, g_State.CurrentUsername, 
                     "SafeStorage system shutting down", STATUS_SUCCESS);

        SecureZeroMemory(g_State.CurrentUsername, sizeof(g_State.CurrentUsername));
        SecureZeroMemory(g_State.LoginAttempts, sizeof(g_State.LoginAttempts));
        g_State.IsUserLoggedIn = FALSE;
        g_State.IsInitialized = FALSE;

        LeaveCriticalSection(&g_State.Lock);
        DeleteCriticalSection(&g_State.Lock);

        CleanupRateLimiter();
        CleanupSessionManager();
        CleanupAccountLockout();
        CloseAuditLog();

        printf("SafeStorage deinitialized successfully.\n");
    }

    return;
}


_Must_inspect_result_
NTSTATUS WINAPI
SafeStorageHandleRegister(
    _In_reads_(UsernameLength) const char* Username,
    _In_range_(5, 10) uint16_t UsernameLength,
    _In_reads_(PasswordLength) const char* Password,
    _In_range_(5, 128) uint16_t PasswordLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char passwordHash[HASH_STRING_LENGTH + 1];
    BYTE salt[SALT_LENGTH];
    char saltedHash[HASH_STRING_LENGTH + 1];

    if (!g_State.IsInitialized)
    {
        printf("SafeStorage not initialized.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Username == NULL || Password == NULL)
    {
        printf("Invalid parameters.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!SanitizeString(Username, UsernameLength, MAX_USERNAME_LENGTH))
    {
        printf("Username contains invalid characters.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_INVALID_PARAMETER,
                              "Registration failed - invalid username characters");
        return STATUS_INVALID_PARAMETER;
    }

    if (!SanitizeString(Password, PasswordLength, MAX_PASSWORD_LENGTH))
    {
        printf("Password contains invalid characters.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_INVALID_PARAMETER,
                              "Registration failed - invalid password characters");
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_State.Lock);

    if (g_State.IsUserLoggedIn)
    {
        printf("Cannot register while user is logged in.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    if (!ValidateUsername(Username, UsernameLength))
    {
        printf("Invalid username. Must be 5-10 characters, alphabetic only (a-zA-Z).\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_INVALID_PARAMETER,
                              "Registration failed - invalid username format");
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (!ValidatePassword(Password, PasswordLength))
    {
        printf("Invalid password. Must be at least 5 characters with:\n");
        printf("        - At least one digit\n");
        printf("        - At least one lowercase letter\n");
        printf("        - At least one uppercase letter\n");
        printf("        - At least one special symbol (!@#$%%^&)\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_INVALID_PARAMETER,
                              "Registration failed - weak password");
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (UserExists(Username, UsernameLength))
    {
        printf("User '%.*s' already exists.\n", (int)UsernameLength, Username);
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_USER_EXISTS,
                              "Registration failed - user already exists: %.*s",
                              (int)UsernameLength, Username);
        status = STATUS_USER_EXISTS;
        goto Cleanup;
    }

    status = GenerateSalt(salt);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to generate salt.\n");
        LogAuditEvent(AUDIT_ERROR, NULL, "Salt generation failed during registration", status);
        goto Cleanup;
    }

    status = HashPasswordWithSalt(Password, PasswordLength, salt, saltedHash);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to hash password with salt.\n");
        LogAuditEvent(AUDIT_ERROR, NULL, "Password hashing failed during registration", status);
        goto Cleanup;
    }

    status = AddUserToFileWithSalt(Username, UsernameLength, salt, saltedHash);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to add user to database.\n");
        LogAuditEvent(AUDIT_ERROR, NULL, "Failed to add user to database", status);
        goto Cleanup;
    }

    status = CreateUserDirectory(Username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to create user directory.\n");
        LogAuditEvent(AUDIT_ERROR, NULL, "Failed to create user directory", status);
        goto Cleanup;
    }

    printf("User '%.*s' registered successfully.\n", (int)UsernameLength, Username);
    
    LogAuditEventFormatted(AUDIT_USER_REGISTER, NULL, STATUS_SUCCESS,
                          "User registered: %.*s", (int)UsernameLength, Username);

Cleanup:
    SecureZeroMemory(passwordHash, sizeof(passwordHash));
    SecureZeroMemory(saltedHash, sizeof(saltedHash));
    SecureZeroMemory(salt, sizeof(salt));
    LeaveCriticalSection(&g_State.Lock);

    return status;
}


_Must_inspect_result_
NTSTATUS WINAPI
SafeStorageHandleLogin(
    _In_reads_(UsernameLength) const char* Username,
    _In_range_(5, 10) uint16_t UsernameLength,
    _In_reads_(PasswordLength) const char* Password,
    _In_range_(5, 128) uint16_t PasswordLength
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!g_State.IsInitialized)
    {
        printf("SafeStorage not initialized.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Username == NULL || Password == NULL)
    {
        printf("Invalid parameters.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!SanitizeString(Username, UsernameLength, MAX_USERNAME_LENGTH))
    {
        printf("Username contains invalid characters.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_INVALID_PARAMETER,
                              "Login failed - invalid username characters");
        return STATUS_INVALID_PARAMETER;
    }

    if (!SanitizeString(Password, PasswordLength, MAX_PASSWORD_LENGTH))
    {
        printf("Password contains invalid characters.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_INVALID_PARAMETER,
                              "Login failed - invalid password characters");
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_State.Lock);

    if (g_State.IsUserLoggedIn)
    {
        printf("User '%s' is already logged in. Please logout first.\n", 
               g_State.CurrentUsername);
        status = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    if (IsAccountLocked(Username, UsernameLength))
    {
        printf("Account is locked due to too many failed login attempts.\n");
        printf("Please wait %d seconds before trying again.\n", LOCKOUT_DURATION_SECONDS);
        
        LogAuditEventFormatted(AUDIT_LOGIN_LOCKED, NULL, STATUS_ACCOUNT_LOCKED_OUT,
                              "Login blocked - account locked: %.*s",
                              (int)UsernameLength, Username);
        
        status = STATUS_ACCOUNT_LOCKED_OUT;
        goto Cleanup;
    }

    if (CheckBruteForceProtection())
    {
        printf("Too many login attempts. Please wait before trying again.\n");
        
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, NULL, STATUS_ACCOUNT_LOCKED_OUT,
                              "Login blocked - brute force protection: %.*s",
                              (int)UsernameLength, Username);
        
        status = STATUS_ACCOUNT_LOCKED_OUT;
        goto Cleanup;
    }

    if (!ValidateUsername(Username, UsernameLength))
    {
        printf("Invalid username format.\n");
        
        RecordLoginAttempt();
        RecordFailedLoginAttempt(Username, UsernameLength);
        
        LogAuditEventFormatted(AUDIT_LOGIN_FAILED, NULL, STATUS_INVALID_PARAMETER,
                              "Login failed - invalid username format: %.*s",
                              (int)UsernameLength, Username);
        
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (!VerifyCredentialsWithSalt(Username, UsernameLength, Password, PasswordLength))
    {
        printf("Invalid username or password.\n");
        
        RecordLoginAttempt();
        RecordFailedLoginAttempt(Username, UsernameLength);
        
        LogAuditEventFormatted(AUDIT_LOGIN_FAILED, NULL, STATUS_LOGON_FAILURE,
                              "Login failed - invalid credentials: %.*s",
                              (int)UsernameLength, Username);
        
        status = STATUS_LOGON_FAILURE;
        goto Cleanup;
    }

    errno_t err = memcpy_s(g_State.CurrentUsername, sizeof(g_State.CurrentUsername), 
                           Username, UsernameLength);
    if (err != 0)
    {
        printf("Failed to copy username to state.\n");
        LogAuditEvent(AUDIT_ERROR, NULL, "Memory copy error during login", STATUS_UNSUCCESSFUL);
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    g_State.CurrentUsername[UsernameLength] = '\0';
    g_State.IsUserLoggedIn = TRUE;

    SecureZeroMemory(g_State.LoginAttempts, sizeof(g_State.LoginAttempts));
    g_State.LoginAttemptIndex = 0;
    
    ResetFailedAttempts(Username, UsernameLength);

    UpdateSessionActivity();

    printf("User '%s' logged in successfully.\n", g_State.CurrentUsername);
    
    LogAuditEventFormatted(AUDIT_LOGIN_SUCCESS, g_State.CurrentUsername, STATUS_SUCCESS,
                          "User logged in: %s", g_State.CurrentUsername);

Cleanup:
    LeaveCriticalSection(&g_State.Lock);

    return status;
}


_Must_inspect_result_
NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char username[MAX_USERNAME_LENGTH + 1];
    errno_t err;

    if (!g_State.IsInitialized)
    {
        printf("SafeStorage not initialized.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&g_State.Lock);

    if (!g_State.IsUserLoggedIn)
    {
        printf("No user is currently logged in.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    err = memcpy_s(username, sizeof(username), 
                   g_State.CurrentUsername, sizeof(g_State.CurrentUsername));
    if (err != 0)
    {
        printf("Failed to copy username during logout.\n");
        LogAuditEvent(AUDIT_ERROR, g_State.CurrentUsername, 
                     "Memory copy error during logout", STATUS_UNSUCCESSFUL);
    }

    printf("User '%s' logged out successfully.\n", g_State.CurrentUsername);
    
    LogAuditEventFormatted(AUDIT_USER_LOGOUT, g_State.CurrentUsername, STATUS_SUCCESS,
                          "User logged out: %s", g_State.CurrentUsername);

    SecureZeroMemory(g_State.CurrentUsername, sizeof(g_State.CurrentUsername));
    g_State.IsUserLoggedIn = FALSE;


Cleanup:
    LeaveCriticalSection(&g_State.Lock);

    return status;
}


_Must_inspect_result_
NTSTATUS WINAPI
SafeStorageHandleStore(
    _In_reads_(SubmissionNameLength) const char* SubmissionName,
    _In_range_(1, 260) uint16_t SubmissionNameLength,
    _In_reads_(SourceFilePathLength) const char* SourceFilePath,
    _In_range_(1, 260) uint16_t SourceFilePathLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char destinationPath[MAX_PATH];
    char userDirPath[MAX_PATH];
    char canonicalSourcePath[MAX_PATH];
    HRESULT hr;
    ULONGLONG fileSize = 0;
    BYTE checksum[CHECKSUM_SIZE];

    if (!g_State.IsInitialized)
    {
        printf("SafeStorage not initialized.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (SubmissionName == NULL || SourceFilePath == NULL)
    {
        printf("Invalid parameters.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!CheckRateLimit())
    {
        printf("Too many commands. Please wait before trying again.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Rate limit exceeded - store command", STATUS_QUOTA_EXCEEDED);
        return STATUS_QUOTA_EXCEEDED;
    }

    if (!ValidatePathSecurity(SubmissionName, SubmissionNameLength, 0))
    {
        printf("Submission name failed security validation.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Invalid submission name", STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidatePathSecurity(SourceFilePath, SourceFilePathLength, 1))
    {
        printf("Source file path failed security validation.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Invalid source path", STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    status = CanonicalizeAndValidatePath(SourceFilePath, SourceFilePathLength, 
                                          canonicalSourcePath, MAX_PATH);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to retrieve source path.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Retrieve path failed", status);
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_State.Lock);

    if (IsSessionExpired())
    {
        ExpireSession();
        LogAuditEvent(AUDIT_SESSION_TIMEOUT, g_State.CurrentUsername, 
                     "Session expired during store", STATUS_TIMEOUT);
        printf("Session expired. Please login again.\n");
        status = STATUS_TIMEOUT;
        goto Cleanup;
    }

    if (!g_State.IsUserLoggedIn)
    {
        printf("No user is logged in. Please login first.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    if (GetFileAttributesA(canonicalSourcePath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("Source file '%s' does not exist.\n", canonicalSourcePath);
        LogAuditEventFormatted(AUDIT_ERROR, g_State.CurrentUsername, STATUS_NO_SUCH_FILE,
                              "File not found: %s", canonicalSourcePath);
        status = STATUS_NO_SUCH_FILE;
        goto Cleanup;
    }

    if (IsSymlinkOrJunction(canonicalSourcePath))
    {
        printf("Symlinks and junctions are not allowed.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Symlink detected in source path", STATUS_INVALID_PARAMETER);
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (!ValidatePathNotInOtherUserDirectory(canonicalSourcePath))
    {
        printf("Cannot store files from another user's directory.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername,
                              STATUS_ACCESS_DENIED,
                              "Attempted to access another user's directory: %s", canonicalSourcePath);
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    if (!CheckFileSizeLimit(canonicalSourcePath, &fileSize))
    {
        printf("File exceeds maximum size limit of 8 GB.\n");
        
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername,
                              STATUS_QUOTA_EXCEEDED,
                              "File exceeds 8GB limit: %.2f GB",
                              (double)fileSize / (1024.0 * 1024.0 * 1024.0));
        
        status = STATUS_QUOTA_EXCEEDED;
        goto Cleanup;
    }

    status = GetUserDirectoryPath(
        g_State.CurrentUsername,
        (uint16_t)strlen(g_State.CurrentUsername),
        userDirPath
    );

    if (!NT_SUCCESS(status))
    {
        printf("Failed to build user directory path.\n");
        LogAuditEvent(AUDIT_ERROR, g_State.CurrentUsername, 
                     "Failed to build user directory path", status);
        goto Cleanup;
    }

    hr = StringCchPrintfA(
        destinationPath,
        MAX_PATH,
        "%s\\%.*s",
        userDirPath,
        (int)SubmissionNameLength,
        SubmissionName
    );

    if (FAILED(hr))
    {
        printf("Failed to build destination path.\n");
        LogAuditEvent(AUDIT_ERROR, g_State.CurrentUsername, 
                     "Failed to build destination path", STATUS_UNSUCCESSFUL);
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    if (!ValidatePathBelongsToCurrentUser(destinationPath))
    {
        printf("Security violation: Attempted to store file outside user directory.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername,
                              STATUS_ACCESS_DENIED,
                              "Unauthorized path access attempt: %s", destinationPath);
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    status = CopyFileWithThreadPool(canonicalSourcePath, destinationPath);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to copy file.\n");
        LogAuditEvent(AUDIT_ERROR, g_State.CurrentUsername, 
                     "File copy failed during store", status);
        goto Cleanup;
    }

    status = CalculateFileChecksum(destinationPath, checksum);
    if (NT_SUCCESS(status))
    {
        status = StoreFileChecksum(destinationPath, checksum);
        if (!NT_SUCCESS(status))
        {
            printf("Failed to store file integrity checksum.\n");
        }
        else
        {
            printf("File integrity checksum stored successfully.\n");
        }
    }
    else
    {
        printf("Failed to calculate file checksum.\n");
    }

    printf("File stored successfully as '%.*s'.\n", 
           (int)SubmissionNameLength, SubmissionName);
    
    LogAuditEventFormatted(AUDIT_FILE_STORE, g_State.CurrentUsername, STATUS_SUCCESS,
                          "File stored: '%.*s' (%.2f KB)",
                          (int)SubmissionNameLength, SubmissionName,
                          (double)fileSize / 1024.0);
    
    RecordCommand();
    
    UpdateSessionActivity();

Cleanup:
    SecureZeroMemory(checksum, sizeof(checksum));
    LeaveCriticalSection(&g_State.Lock);

    return status;
}


_Must_inspect_result_
NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    _In_reads_(SubmissionNameLength) const char* SubmissionName,
    _In_range_(1, 260) uint16_t SubmissionNameLength,
    _In_reads_(DestinationFilePathLength) const char* DestinationFilePath,
    _In_range_(1, 260) uint16_t DestinationFilePathLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char sourcePath[MAX_PATH];
    char userDirPath[MAX_PATH];
    char canonicalDestPath[MAX_PATH];
    HRESULT hr;
    BOOL hasMetadata = FALSE;

    if (!g_State.IsInitialized)
    {
        printf("SafeStorage not initialized.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (SubmissionName == NULL || DestinationFilePath == NULL)
    {
        printf("Invalid parameters.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!CheckRateLimit())
    {
        printf("Too many commands. Please wait before trying again.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Rate limit exceeded - retrieve command", STATUS_QUOTA_EXCEEDED);
        return STATUS_QUOTA_EXCEEDED;
    }

    if (!ValidatePathSecurity(SubmissionName, SubmissionNameLength, 0))
    {
        printf("Submission name failed security validation.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Invalid submission name", STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidatePathSecurity(DestinationFilePath, DestinationFilePathLength, 1))
    {
        printf("Destination file path failed security validation.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Invalid destination path", STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    status = CanonicalizeAndValidatePath(DestinationFilePath, DestinationFilePathLength,
                                          canonicalDestPath, MAX_PATH);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to retrieve destination path.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Retreive path failed", status);
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_State.Lock);

    if (IsSessionExpired())
    {
        ExpireSession();
        LogAuditEvent(AUDIT_SESSION_TIMEOUT, g_State.CurrentUsername, 
                     "Session expired during retrieve", STATUS_TIMEOUT);
        printf("Session expired. Please login again.\n");
        status = STATUS_TIMEOUT;
        goto Cleanup;
    }

    if (!g_State.IsUserLoggedIn)
    {
        printf("No user is logged in. Please login first.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    status = GetUserDirectoryPath(
        g_State.CurrentUsername,
        (uint16_t)strlen(g_State.CurrentUsername),
        userDirPath
    );

    if (!NT_SUCCESS(status))
    {
        printf("Failed to build user directory path.\n");
        goto Cleanup;
    }

    hr = StringCchPrintfA(
        sourcePath,
        MAX_PATH,
        "%s\\%.*s",
        userDirPath,
        (int)SubmissionNameLength,
        SubmissionName
    );

    if (FAILED(hr))
    {
        printf("Failed to build source path.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    if (!ValidatePathBelongsToCurrentUser(sourcePath))
    {
        printf("Attempted to retrieve file from another user's directory.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername,
                              STATUS_ACCESS_DENIED,
                              "Unauthorized path access attempt: %s", sourcePath);
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    if (GetFileAttributesA(sourcePath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("Submission '%.*s' does not exist in your directory.\n", 
               (int)SubmissionNameLength, SubmissionName);
        printf("Looking for: %s\n", sourcePath);
        LogAuditEvent(AUDIT_ERROR, g_State.CurrentUsername, 
                     "File not found for retrieve", STATUS_NO_SUCH_FILE);
        status = STATUS_NO_SUCH_FILE;
        goto Cleanup;
    }

    if (IsSymlinkOrJunction(sourcePath))
    {
        printf("Symlinks and junctions are not allowed.\n");
        LogAuditEvent(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername, 
                     "Symlink detected in source", STATUS_INVALID_PARAMETER);
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (!ValidatePathNotInOtherUserDirectory(canonicalDestPath))
    {
        printf("Cannot retrieve files to another user's directory.\n");
        LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername,
                              STATUS_ACCESS_DENIED,
                              "Attempted to write to another user's directory: %s", canonicalDestPath);
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    if (!VerifyFileIntegrity(sourcePath, &hasMetadata))
    {
        if (hasMetadata)
        {
            printf("File integrity check FAILED!\n");
            printf("File may be corrupted or tampered.\n");
            
            LogAuditEventFormatted(AUDIT_SECURITY_VIOLATION, g_State.CurrentUsername,
                                  STATUS_DATA_ERROR,
                                  "File integrity check failed: %.*s",
                                  (int)SubmissionNameLength, SubmissionName);
            
            status = STATUS_DATA_ERROR;
            goto Cleanup;
        }
    }

    status = CopyFileWithThreadPool(sourcePath, canonicalDestPath);
    if (!NT_SUCCESS(status))
    {
        printf("Failed to copy file from '%s' to '%s'.\n", sourcePath, canonicalDestPath);
        LogAuditEvent(AUDIT_ERROR, g_State.CurrentUsername, 
                     "File copy failed during retrieve", status);
        goto Cleanup;
    }

    printf("File retrieved successfully to '%s'.\n", canonicalDestPath);
    
    LogAuditEventFormatted(AUDIT_FILE_RETRIEVE, g_State.CurrentUsername, STATUS_SUCCESS,
                          "Retrieved file '%.*s' to '%s'",
                          (int)SubmissionNameLength, SubmissionName, canonicalDestPath);
    
    RecordCommand();
    
    UpdateSessionActivity();

Cleanup:
    LeaveCriticalSection(&g_State.Lock);

    return status;
}
