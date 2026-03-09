#include "SafeStorageInternal.h"
#include "FileIntegrity.h"
#include <string.h>

#define CHECKSUM_SIZE 32
#define INTEGRITY_EXTENSION ".sha256"


_Must_inspect_result_
NTSTATUS
CalculateFileChecksum(
    _In_z_ const char* FilePath,
    _Out_writes_bytes_(CHECKSUM_SIZE) BYTE* Checksum
)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE buffer[4096];
    DWORD bytesRead;

    if (FilePath == NULL || Checksum == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    hFile = CreateFileA(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Cannot open file for checksum calculation.\n");
        return STATUS_NO_SUCH_FILE;
    }

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

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0)
    {
        status = BCryptHashData(hHash, buffer, bytesRead, 0);
        if (!NT_SUCCESS(status))
        {
            goto Cleanup;
        }
    }

    status = BCryptFinishHash(hHash, Checksum, CHECKSUM_SIZE, 0);

Cleanup:
    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (hAlgorithm)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    SecureZeroMemory(buffer, sizeof(buffer));

    return status;
}


_Must_inspect_result_
NTSTATUS
StoreFileChecksum(
    _In_z_ const char* FilePath,
    _In_reads_bytes_(CHECKSUM_SIZE) const BYTE* Checksum
)
{
    char metadataPath[MAX_PATH];
    FILE* metaFile = NULL;
    errno_t err;
    size_t bytesWritten;

    if (FilePath == NULL || Checksum == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (sprintf_s(metadataPath, MAX_PATH, "%s%s", FilePath, INTEGRITY_EXTENSION) < 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    err = fopen_s(&metaFile, metadataPath, "wb");
    if (err != 0 || metaFile == NULL)
    {
        printf("Cannot create integrity metadata file.\n");
        return STATUS_UNSUCCESSFUL;
    }

    bytesWritten = fwrite(Checksum, sizeof(BYTE), CHECKSUM_SIZE, metaFile);
    if (bytesWritten != CHECKSUM_SIZE)
    {
        printf("Failed to write complete checksum. Expected %d bytes, wrote %zu bytes.\n", 
               CHECKSUM_SIZE, bytesWritten);
        fclose(metaFile);
        DeleteFileA(metadataPath);
        return STATUS_UNSUCCESSFUL;
    }

    if (fflush(metaFile) != 0)
    {
        printf("Failed to flush checksum data to disk.\n");
        fclose(metaFile);
        DeleteFileA(metadataPath);
        return STATUS_UNSUCCESSFUL;
    }

    fclose(metaFile);

    printf("File integrity checksum stored.\n");
    return STATUS_SUCCESS;
}


_Must_inspect_result_
NTSTATUS
LoadFileChecksum(
    _In_z_ const char* FilePath,
    _Out_writes_bytes_(CHECKSUM_SIZE) BYTE* Checksum
)
{
    char metadataPath[MAX_PATH];
    FILE* metaFile = NULL;
    errno_t err;
    size_t bytesRead;
    long fileSize;

    if (FilePath == NULL || Checksum == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SecureZeroMemory(Checksum, CHECKSUM_SIZE);

    if (sprintf_s(metadataPath, MAX_PATH, "%s%s", FilePath, INTEGRITY_EXTENSION) < 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    err = fopen_s(&metaFile, metadataPath, "rb");
    if (err != 0 || metaFile == NULL)
    {
        printf("No integrity metadata found for file.\n");
        return STATUS_NOT_FOUND;
    }

    if (fseek(metaFile, 0, SEEK_END) != 0)
    {
        printf("Failed to seek to end of metadata file.\n");
        fclose(metaFile);
        return STATUS_DATA_ERROR;
    }

    fileSize = ftell(metaFile);
    if (fileSize != CHECKSUM_SIZE)
    {
        printf("Invalid checksum file size: %ld bytes (expected %d bytes).\n", 
               fileSize, CHECKSUM_SIZE);
        fclose(metaFile);
        return STATUS_DATA_ERROR;
    }

    if (fseek(metaFile, 0, SEEK_SET) != 0)
    {
        printf("Failed to seek to beginning of metadata file.\n");
        fclose(metaFile);
        return STATUS_DATA_ERROR;
    }

    bytesRead = fread(Checksum, sizeof(BYTE), CHECKSUM_SIZE, metaFile);
    
    if (bytesRead != CHECKSUM_SIZE)
    {
        printf("Failed to read complete checksum. Expected %d bytes, read %zu bytes.\n", 
               CHECKSUM_SIZE, bytesRead);
        
        if (ferror(metaFile))
        {
            printf("File read error occurred.\n");
        }
        else if (feof(metaFile))
        {
            printf("Unexpected end of file.\n");
        }
        
        SecureZeroMemory(Checksum, CHECKSUM_SIZE);
        fclose(metaFile);
        return STATUS_DATA_ERROR;
    }

    fclose(metaFile);
    return STATUS_SUCCESS;
}


_Must_inspect_result_
BOOL
VerifyFileIntegrity(
    _In_z_ const char* FilePath,
    _Out_opt_ BOOL* HasMetadata
)
{
    BYTE storedChecksum[CHECKSUM_SIZE];
    BYTE computedChecksum[CHECKSUM_SIZE];
    NTSTATUS status;
    BOOL match = FALSE;

    if (FilePath == NULL)
    {
        return FALSE;
    }

    status = LoadFileChecksum(FilePath, storedChecksum);
    if (!NT_SUCCESS(status))
    {
        if (HasMetadata != NULL)
        {
            *HasMetadata = FALSE;
        }

        if (status == STATUS_NOT_FOUND)
        {
            printf("File has no integrity metadata (not verified).\n");
        }
        else
        {
            printf("Cannot load integrity metadata.\n");
        }

        return FALSE;
    }

    if (HasMetadata != NULL)
    {
        *HasMetadata = TRUE;
    }

    status = CalculateFileChecksum(FilePath, computedChecksum);
    if (!NT_SUCCESS(status))
    {
        printf("Cannot calculate file checksum.\n");
        SecureZeroMemory(storedChecksum, sizeof(storedChecksum));
        return FALSE;
    }

    match = (memcmp(storedChecksum, computedChecksum, CHECKSUM_SIZE) == 0);

    if (match)
    {
        printf("File integrity verified - no tampering detected.\n");
    }
    else
    {
        printf("FILE INTEGRITY CHECK FAILED!\n");
        printf("File may have been tampered with or corrupted.\n");
    }

    SecureZeroMemory(storedChecksum, sizeof(storedChecksum));
    SecureZeroMemory(computedChecksum, sizeof(computedChecksum));

    return match;
}


_Must_inspect_result_
NTSTATUS
DeleteFileChecksum(
    _In_z_ const char* FilePath
)
{
    char metadataPath[MAX_PATH];

    if (FilePath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (sprintf_s(metadataPath, MAX_PATH, "%s%s", FilePath, INTEGRITY_EXTENSION) < 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (!DeleteFileA(metadataPath))
    {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}