#ifndef _ANTICUCKOO_H__
#define _ANTICUCKOO_H__

#include <stdlib.h>
#include <windows.h>
#include <capstone.h>
#include "misc.h"

#define VERSION_STRING_EXTENDED "1.0 alpha"

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

int AntiCuckoo(int argc, _TCHAR* argv[]);
int SuspiciusDataInMyMemory(bool * found);
int filterExceptionExecuteHandler(int code, PEXCEPTION_POINTERS ex);
void Report(char * format, ...);
int Hooks(bool * found);
int CheckHook(bool * found, unsigned char * address);

#endif /* _ANTICUCKOO_H__ */