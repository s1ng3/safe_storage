#include "SafeStorageInternal.h"
#include "PathSecurity.h"
#include <string.h>
#include <ctype.h>

static const char* g_DangerousExtensions[] = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".ws", ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2",
    ".ps2xml", ".psc1", ".psc2", ".msh", ".msh1", ".msh2", ".mshxml",
    ".msh1xml", ".msh2xml", ".scf", ".lnk", ".inf", ".reg", ".dll",
    ".cpl", ".msi", ".msp", ".hta", ".jar", ".app", ".deb", ".rpm"
};

#define DANGEROUS_EXTENSION_COUNT (sizeof(g_DangerousExtensions) / sizeof(g_DangerousExtensions[0]))

_Must_inspect_result_
NTSTATUS
CanonicalizeAndValidatePath(
    _In_reads_(InputLength) const char* InputPath,
    _In_ SIZE_T InputLength,
    _Out_writes_z_(BufferSize) char* CanonicalPath,
    _In_ SIZE_T BufferSize
)
{
    DWORD result;
    const char* ptr;
    
    if (InputPath == NULL || CanonicalPath == NULL || BufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputLength == 0 || InputLength >= BufferSize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ptr = InputPath;
    while (*ptr)
    {
        if (ptr[0] == '.' && ptr[1] == '.')
        {
            if (ptr == InputPath || ptr[-1] == '\\' || ptr[-1] == '/')
            {
                if (ptr[2] == '\0' || ptr[2] == '\\' || ptr[2] == '/')
                {
                    printf("Path traversal detected: %s\n", InputPath);
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }
        ptr++;
    }

    result = GetFullPathNameA(InputPath, (DWORD)BufferSize, CanonicalPath, NULL);
    if (result == 0 || result >= BufferSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
BOOL
ValidateFileExtension(
    _In_reads_(Length) const char* Filename,
    _In_ SIZE_T Length
)
{
    const char* extension;
    SIZE_T extLen;

    if (Filename == NULL || Length == 0)
    {
        return FALSE;
    }

    extension = strrchr(Filename, '.');
    if (extension == NULL)
    {
        return TRUE;
    }

    extLen = strlen(extension);
    if (extLen == 0 || extLen > 10)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < DANGEROUS_EXTENSION_COUNT; i++)
    {
        if (_stricmp(extension, g_DangerousExtensions[i]) == 0)
        {
            printf("Dangerous file extension blocked: %s\n", extension);
            return FALSE;
        }
    }

    const char* prevDot = extension - 1;
    while (prevDot > Filename && *prevDot != '.')
    {
        prevDot--;
    }

    if (*prevDot == '.' && prevDot > Filename)
    {
        char tempExt[12];
        SIZE_T tempExtLen = extension - prevDot;
        if (tempExtLen < sizeof(tempExt))
        {
            memcpy(tempExt, prevDot, tempExtLen);
            tempExt[tempExtLen] = '\0';
            
            for (SIZE_T i = 0; i < DANGEROUS_EXTENSION_COUNT; i++)
            {
                if (_stricmp(tempExt, g_DangerousExtensions[i]) == 0)
                {
                    printf("Double extension attack blocked: %s\n", Filename);
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
ValidateNoFormatSpecifiers(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
)
{
    if (Input == NULL)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < Length; i++)
    {
        if (Input[i] == '%')
        {
            if (i + 1 < Length)
            {
                char next = Input[i + 1];
                if (next == 's' || next == 'd' || next == 'i' || next == 'u' ||
                    next == 'x' || next == 'X' || next == 'f' || next == 'c' ||
                    next == 'p' || next == 'n' || next == 'l' || next == 'h' ||
                    next == 'L' || next == 'z' || next == 't' || next == '%')
                {
                    printf("Format specifier detected: %%%c\n", next);
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
ValidateNoCommandInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
)
{
    if (Input == NULL)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < Length; i++)
    {
        char c = Input[i];
        
        if (c == '|' || c == '&' || c == ';' || c == '`' ||
            c == '$' || c == '(' || c == ')' || c == '<' ||
            c == '>' || c == '\n' || c == '\r' || c == '~')
        {
            printf("Command injection character detected: 0x%02X\n", (unsigned char)c);
            return FALSE;
        }
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
ValidateNoSQLInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
)
{
    if (Input == NULL)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < Length; i++)
    {
        char c = Input[i];
        
        if (c == '\'' || c == '"')
        {
            printf("SQL injection character detected: %c\n", c);
            return FALSE;
        }
    }

    if (strstr(Input, "--") != NULL ||
        strstr(Input, "/*") != NULL ||
        strstr(Input, "*/") != NULL)
    {
        printf("SQL comment pattern detected\n");
        return FALSE;
    }

    char upperInput[256];
    SIZE_T copyLen = Length < sizeof(upperInput) - 1 ? Length : sizeof(upperInput) - 1;
    
    for (SIZE_T i = 0; i < copyLen; i++)
    {
        upperInput[i] = (char)toupper((unsigned char)Input[i]);
    }
    upperInput[copyLen] = '\0';

    if (strstr(upperInput, "UNION") != NULL ||
        strstr(upperInput, "SELECT") != NULL ||
        strstr(upperInput, "INSERT") != NULL ||
        strstr(upperInput, "UPDATE") != NULL ||
        strstr(upperInput, "DELETE") != NULL ||
        strstr(upperInput, "DROP") != NULL ||
        strstr(upperInput, "EXEC") != NULL ||
        strstr(upperInput, "EXECUTE") != NULL)
    {
        printf("SQL keyword detected\n");
        return FALSE;
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
ValidateNoDelimiterInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
)
{
    if (Input == NULL)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < Length; i++)
    {
        char c = Input[i];
        
        if (c == '\n' || c == '\r' || c == '\0' || c == '\t')
        {
            printf("Delimiter injection detected: 0x%02X\n", (unsigned char)c);
            return FALSE;
        }
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
ValidateNoNullInjection(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length
)
{
    if (Input == NULL)
    {
        return FALSE;
    }

    SIZE_T actualLength = strlen(Input);
    if (actualLength != Length)
    {
        printf("NUL injection detected: expected %zu bytes, got %zu\n",
               Length, actualLength);
        return FALSE;
    }

    for (SIZE_T i = 0; i < Length; i++)
    {
        if (Input[i] == '\0')
        {
            printf("Embedded NUL byte detected at position %zu\n", i);
            return FALSE;
        }
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
IsSymlinkOrJunction(
    _In_z_ const char* Path
)
{
    DWORD attributes;

    if (Path == NULL)
    {
        return FALSE;
    }

    attributes = GetFileAttributesA(Path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return FALSE;
    }

    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        printf("Symlink/Junction detected: %s\n", Path);
        return TRUE;
    }

    return FALSE;
}

_Must_inspect_result_
BOOL
ValidatePathSecurity(
    _In_reads_(InputLength) const char* InputPath,
    _In_ SIZE_T InputLength,
    _In_ INT PathType
)
{
    if (InputPath == NULL || InputLength == 0)
    {
        return FALSE;
    }

    if (InputPath[InputLength] != '\0')
    {
        printf("String not properly null-terminated\n");
        return FALSE;
    }

    if (!ValidateNoNullInjection(InputPath, InputLength))
    {
        return FALSE;
    }

    if (strstr(InputPath, "..") != NULL)
    {
        printf("Path traversal detected\n");
        return FALSE;
    }

    if (!ValidateNoFormatSpecifiers(InputPath, InputLength))
    {
        return FALSE;
    }

    if (!ValidateNoCommandInjection(InputPath, InputLength))
    {
        return FALSE;
    }

    if (!ValidateNoDelimiterInjection(InputPath, InputLength))
    {
        return FALSE;
    }

    if (PathType == 0)
    {
        if (!ValidateFileExtension(InputPath, InputLength))
        {
            return FALSE;
        }

        if (strchr(InputPath, '\\') != NULL || strchr(InputPath, '/') != NULL)
        {
            printf("Path separators not allowed in submission names\n");
            return FALSE;
        }
    }

    return TRUE;
}

_Must_inspect_result_
BOOL
SanitizePathString(
    _In_reads_(Length) const char* Input,
    _In_ SIZE_T Length,
    _In_ SIZE_T MaxLength
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

    if (!ValidateNoNullInjection(Input, Length))
    {
        return FALSE;
    }

    if (!ValidateNoFormatSpecifiers(Input, Length))
    {
        return FALSE;
    }

    if (!ValidateNoCommandInjection(Input, Length))
    {
        return FALSE;
    }

    if (!ValidateNoSQLInjection(Input, Length))
    {
        return FALSE;
    }

    if (!ValidateNoDelimiterInjection(Input, Length))
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < Length; i++)
    {
        unsigned char c = (unsigned char)Input[i];
        
        if (c < 32 || c > 126)
        {
            if (c != '\0')
            {
                printf("Non-printable character detected: 0x%02X\n", c);
                return FALSE;
            }
        }
    }

    return TRUE;
}
