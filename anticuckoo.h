#ifndef _ANTICUCKOO_H__
#define _ANTICUCKOO_H__

#include <stdlib.h>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <capstone.h>
#include "misc.h"

using namespace std;
#define VERSION_STRING_EXTENDED "1.1 alpha"

#define SUSP_CTRL_STRING "_CTRL"
#define DATA_SUSP_ENTRY_STRING(instring) {instring SUSP_CTRL_STRING, sizeof(instring) - 1}

#define API_TABLE_ENTRY_NTDLL(name) {NULL, #name, "ntdll.dll", true}
#define API_TABLE_ENTRY_KERNEL32(name) {(unsigned char *)name, #name, "kernel32.dll", false}

typedef struct
{
	unsigned char * api_addr;
	char * api_name;
	char * lib_name;
	bool need_resolv;
} API_TABLE_t;

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	WORD * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
     (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
     (p)->RootDirectory = r;                             \
     (p)->Attributes = a;                                \
     (p)->ObjectName = n;                                \
     (p)->SecurityDescriptor = s;                        \
     (p)->SecurityQualityOfService = NULL;               \
     }

typedef NTSTATUS(WINAPI *NtCreateFile_t)(
	__out     PHANDLE FileHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt  PLARGE_INTEGER AllocationSize,
	__in      ULONG FileAttributes,
	__in      ULONG ShareAccess,
	__in      ULONG CreateDisposition,
	__in      ULONG CreateOptions,
	__in      PVOID EaBuffer,
	__in      ULONG EaLength
	);

#define OBJ_CASE_INSENSITIVE    0x00000040L
#define FILE_OPEN_IF 0x00000003
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020 
#define FILE_NON_DIRECTORY_FILE                 0x00000040 

typedef NTSTATUS(WINAPI *RtlInitUnicodeString_t)(PUNICODE_STRING dst_str, PCWSTR src_str);

int AntiCuckoo(int argc, _TCHAR* argv[]);
int SuspiciusDataInMyMemory(bool * found);
int filterExceptionExecuteHandler(int code, PEXCEPTION_POINTERS ex);
void Report(char * format, ...);
int Hooks(bool * found);
int CheckHook(bool * found, unsigned char * address);
int StackRetCrash(void);
int UnhkThreadCrash(void);
int GetInstructionOut(char * out_str, size_t out_str_size, cs_insn *insn);
int HKActivOldStackCrash(void);



#endif /* _ANTICUCKOO_H__ */