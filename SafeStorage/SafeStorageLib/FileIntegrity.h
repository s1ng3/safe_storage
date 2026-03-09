#ifndef _FILE_INTEGRITY_H_
#define _FILE_INTEGRITY_H_

#include "includes.h"

EXTERN_C_START;

#define CHECKSUM_SIZE 32

_Must_inspect_result_
NTSTATUS
CalculateFileChecksum(
    _In_z_ const char* FilePath,
    _Out_writes_bytes_(CHECKSUM_SIZE) BYTE* Checksum
);

_Must_inspect_result_
NTSTATUS
StoreFileChecksum(
    _In_z_ const char* FilePath,
    _In_reads_bytes_(CHECKSUM_SIZE) const BYTE* Checksum
);

_Must_inspect_result_
BOOL
VerifyFileIntegrity(
    _In_z_ const char* FilePath,
    _Out_opt_ BOOL* HasMetadata
);

_Must_inspect_result_
NTSTATUS
DeleteFileChecksum(
    _In_z_ const char* FilePath
);

EXTERN_C_END;

#endif // _FILE_INTEGRITY_H_
