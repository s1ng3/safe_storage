#include "SafeStorageInternal.h"
#include "FileSizeLimits.h"
#include <string.h>

#define MAX_FILE_SIZE (8ULL * 1024 * 1024 * 1024)
#define BYTES_PER_KB 1024
#define BYTES_PER_MB (1024 * 1024)
#define BYTES_PER_GB (1024ULL * 1024 * 1024)


_Must_inspect_result_
NTSTATUS
GetFileSizeEx64(
    _In_z_ const char* FilePath,
    _Out_ ULONGLONG* FileSize
)
{
    HANDLE hFile;
    LARGE_INTEGER size;

    if (FilePath == NULL || FileSize == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    hFile = CreateFileA(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Cannot access file to check size.\n");
        return STATUS_NO_SUCH_FILE;
    }

    if (!GetFileSizeEx(hFile, &size))
    {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    CloseHandle(hFile);

    *FileSize = (ULONGLONG)size.QuadPart;
    return STATUS_SUCCESS;
}


_Must_inspect_result_
BOOL
ValidateFileSize(
    _In_z_ const char* FilePath
)
{
    NTSTATUS status;
    ULONGLONG fileSize;

    status = GetFileSizeEx64(FilePath, &fileSize);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    if (fileSize > MAX_FILE_SIZE)
    {
        printf("File exceeds maximum size limit.\n");
        printf("File size: ");
        PrintFileSize(fileSize);
        printf("Maximum allowed: ");
        PrintFileSize(MAX_FILE_SIZE);
        return FALSE;
    }

    return TRUE;
}


_Must_inspect_result_
BOOL
CheckFileSizeLimit(
    _In_z_ const char* FilePath,
    _Out_opt_ ULONGLONG* ActualSize
)
{
    NTSTATUS status;
    ULONGLONG fileSize;
    BOOL withinLimit;

    status = GetFileSizeEx64(FilePath, &fileSize);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    if (ActualSize != NULL)
    {
        *ActualSize = fileSize;
    }

    withinLimit = (fileSize <= MAX_FILE_SIZE);

    if (!withinLimit)
    {
        printf("File size exceeds 8 GB limit (%.2f GB).\n",
               (double)fileSize / BYTES_PER_GB);
    }
    else
    {
        printf("File size: ");
        PrintFileSize(fileSize);
    }

    return withinLimit;
}


VOID
PrintFileSize(
    _In_ ULONGLONG FileSize
)
{
    if (FileSize >= BYTES_PER_GB)
    {
        printf("%.2f GB\n", (double)FileSize / BYTES_PER_GB);
    }
    else if (FileSize >= BYTES_PER_MB)
    {
        printf("%.2f MB\n", (double)FileSize / BYTES_PER_MB);
    }
    else if (FileSize >= BYTES_PER_KB)
    {
        printf("%.2f KB\n", (double)FileSize / BYTES_PER_KB);
    }
    else
    {
        printf("%llu bytes\n", FileSize);
    }
}


_Must_inspect_result_
ULONGLONG
GetMaximumFileSize(
    VOID
)
{
    return MAX_FILE_SIZE;
}


_Must_inspect_result_
BOOL
IsFileSizeValid(
    _In_ ULONGLONG FileSize
)
{
    return (FileSize <= MAX_FILE_SIZE);
}