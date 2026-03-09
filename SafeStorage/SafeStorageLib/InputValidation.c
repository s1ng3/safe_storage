#include "SafeStorageInternal.h"
#include "InputValidation.h"
#include <string.h>

#define MAX_COMMAND_LENGTH 10
#define MAX_ARG_LENGTH 260


_Must_inspect_result_
BOOL
ValidateInputLength(
    _In_z_ const char* Input,
    _In_ SIZE_T MaxLength,
    _Out_opt_ SIZE_T* ActualLength
)
{
    SIZE_T len;

    if (Input == NULL)
    {
        printf("NULL input provided.\n");
        return FALSE;
    }

    len = strnlen(Input, MaxLength + 1);

    if (len > MaxLength)
    {
        printf("Input exceeds maximum length (%zu > %zu)\n",
               len, MaxLength);
        return FALSE;
    }

    if (ActualLength != NULL)
    {
        *ActualLength = len;
    }

    return TRUE;
}


_Must_inspect_result_
NTSTATUS
SecureReadInput(
    _Out_writes_z_(BufferSize) char* Buffer,
    _In_ SIZE_T BufferSize,
    _Out_ SIZE_T* BytesRead
)
{
    SIZE_T len;

    if (Buffer == NULL || BytesRead == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (BufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SecureZeroMemory(Buffer, BufferSize);

    if (fgets(Buffer, (int)BufferSize, stdin) == NULL)
    {
        if (feof(stdin))
        {
            return STATUS_END_OF_FILE;
        }
        return STATUS_UNSUCCESSFUL;
    }

    len = strnlen(Buffer, BufferSize);

    if (len > 0 && Buffer[len - 1] == '\n')
    {
        Buffer[len - 1] = '\0';
        len--;
    }

    if (len > 0 && Buffer[len - 1] == '\r')
    {
        Buffer[len - 1] = '\0';
        len--;
    }

    *BytesRead = len;
    return STATUS_SUCCESS;
}


_Must_inspect_result_
BOOL
ValidateCommandInput(
    _In_z_ const char* Command
)
{
    if (!ValidateInputLength(Command, MAX_COMMAND_LENGTH, NULL))
    {
        printf("Command length invalid (max %d characters).\n",
               MAX_COMMAND_LENGTH);
        return FALSE;
    }

    return TRUE;
}


_Must_inspect_result_
BOOL
ValidateArgumentInput(
    _In_z_ const char* Argument
)
{
    if (!ValidateInputLength(Argument, MAX_ARG_LENGTH, NULL))
    {
        printf("Argument length invalid (max %d characters).\n",
               MAX_ARG_LENGTH);
        return FALSE;
    }

    return TRUE;
}


_Must_inspect_result_
BOOL
ValidateStringNotEmpty(
    _In_z_ const char* Input
)
{
    if (Input == NULL || Input[0] == '\0')
    {
        printf("Empty input provided.\n");
        return FALSE;
    }

    return TRUE;
}


_Must_inspect_result_
BOOL
ValidateStringRange(
    _In_z_ const char* Input,
    _In_ SIZE_T MinLength,
    _In_ SIZE_T MaxLength
)
{
    SIZE_T len;

    if (Input == NULL)
    {
        return FALSE;
    }

    len = strnlen(Input, MaxLength + 1);

    if (len < MinLength)
    {
        printf("Input too short (min %zu characters required).\n",
               MinLength);
        return FALSE;
    }

    if (len > MaxLength)
    {
        printf("Input too long (max %zu characters allowed).\n",
               MaxLength);
        return FALSE;
    }

    return TRUE;
}