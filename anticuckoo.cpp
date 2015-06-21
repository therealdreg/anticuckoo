#include "stdafx.h"
#include "anticuckoo.h"

int AntiCuckoo(int argc, _TCHAR* argv[])
{
	verbose = false;
	bool found;

	OutInfo(
		"Anticukoo %s\n"
		"By David Reguera Garcia aka Dreg - Dreg@fr33project.org\n"
		"http://www.fr33project.org/\n"
		"-\n"
		, 
		VERSION_STRING_EXTENDED
	);

	if (Hooks(&found) == 0)
	{
		OutInfo("Hooks %s", found ? "FOUND" : "NOT FOUND");
		if (found)
			Report("Hooks");
	}

	if (SuspiciusDataInMyMemory(&found) == 0)
	{
		OutInfo("SuspiciusDataInMyMemory %s", found ? "FOUND" :"NOT FOUND");
		if (found)
			Report("SuspiciusDataInMyMemory");
	}

	return 0;
}

int Hooks(bool * found)
{
	API_TABLE_t api_table[] =
	{
		API_TABLE_ENTRY_KERNEL32(CreateDirectoryExW),

		API_TABLE_ENTRY_NTDLL(NtQueryDirectoryFile),
		API_TABLE_ENTRY_NTDLL(NtDeleteFile),
		API_TABLE_ENTRY_NTDLL(NtWriteFile),
		API_TABLE_ENTRY_NTDLL(NtReadFile),
		API_TABLE_ENTRY_NTDLL(NtCreateFile),
		API_TABLE_ENTRY_NTDLL(NtSetInformationFile)
	};

	*found = false;

	OutInfo("Searching cuckoo hooks");

	for (int i = 0; i < ARRAYSIZE(api_table); i++)
	{
		if (api_table[i].need_resolv == true)
		{ 
			api_table[i].api_addr = NULL;
			api_table[i].api_addr = (unsigned char *) GetProcAddress(LoadLibraryA(api_table[i].lib_name), api_table[i].api_name);
		}
		if (api_table[i].api_addr != NULL)
		{
			OutInfo("Checking 0x%08X %s (S: 0x%016llX)", api_table[i].api_addr, api_table[i].api_name, *((DWORD64 *)api_table[i].api_addr));
			CheckHook(found, api_table[i].api_addr);
		}
	}

	return 0;
}


int CheckHook(bool * found, unsigned char * address)
{
	*found = true;

	if (address[0] == 0xE9)
	{
		OutInfo("hook_api_jmp_direct Detected!");
		Report("hook_api_jmp_direct");
	}
	else if (address[0] == 0x90 && address[1] == 0xE9)
	{
		OutInfo("hook_api_nop_jmp_direct Detected!");
		Report("hook_api_nop_jmp_direct");
	}
	else if (address[0] == 0x8B && address[1] == 0xFF && address[2] == 0xE9)
	{
		OutInfo("hook_api_hotpatch_jmp_direct Detected!");
		Report("hook_api_hotpatch_jmp_direct");
	}
	else if (address[0] == 0x68 && address[5] == 0xC3)
	{
		OutInfo("hook_api_push_retn Detected!");
		Report("hook_api_push_retn");
	}
	else if (address[0] == 0x90 && address[1] == 0x68 && address[6] == 0xC3)
	{
		OutInfo("hook_api_nop_push_retn Detected!");
		Report("hook_api_nop_push_retn");
	}
	else if (address[0] == 0xFF && address[1] == 0x25)
	{
		OutInfo("hook_api_jmp_indirect Detected!");
		Report("hook_api_jmp_indirect");
	}
	else if (address[0] == 0x8B && address[1] == 0xFF && address[2] == 0xFF && address[3] == 0x25)
	{
		OutInfo("hook_api_hotpatch_jmp_indirect Detected!");
		Report("hook_api_hotpatch_jmp_indirect");
	}
	else if (address[0] == 0xB8 && address[5] == 0xFF && address[6] == 0xE0)
	{
		OutInfo("hook_api_mov_eax_jmp_eax Detected!");
		Report("hook_api_mov_eax_jmp_eax");
	}
	else if (address[0] == 0xB8 && address[5] == 0x50 && address[6] == 0xC3)
	{
		OutInfo("hook_api_mov_eax_push_retn Detected!");
		Report("hook_api_mov_eax_push_retn");
	}
	else if (address[0] == 0xA1 && address[5] == 0xFF && address[6] == 0xE0)
	{
		OutInfo("hook_api_mov_eax_indirect_jmp_eax Detected!");
		Report("hook_api_mov_eax_indirect_jmp_eax");
	}
	else if (address[0] == 0xA1 && address[5] == 0x50 && address[6] == 0xC3)
	{
		OutInfo("hook_api_mov_eax_indirect_jmp_eax Detected!");
		Report("hook_api_mov_eax_indirect_jmp_eax");
	}
	else if (address[0] == 0x90 && address[1] == 0x90 && address[3] == 0xE9)
	{
		OutInfo("hook_api_special_jmp Detected!");
		Report("hook_api_special_jmp");
	}
	else if (address[5] == 0xFF && address[6] == 0x25)
	{
		OutInfo("hook_api_native_jmp_indirect Detected!");
		Report("hook_api_native_jmp_indirect");
	}
	else
	{
		*found = false;
	}

	return 0;
}

int SuspiciusDataInMyMemory(bool * found)
{
	// TODO: HASH STUFF HERE TO REMOVE _CTRL CRAP.
	DATA_ENTRY_t suspicius_data[] =
	{
		DATA_SUSP_ENTRY_STRING("cuckoomon"),
		DATA_SUSP_ENTRY_STRING("New_NtDeleteFile"),
		DATA_SUSP_ENTRY_STRING("retaddr-check"),
		DATA_SUSP_ENTRY_STRING("HookHandle"),
		DATA_SUSP_ENTRY_STRING("nhook detection"),
		DATA_SUSP_ENTRY_STRING("distorm"),
		DATA_SUSP_ENTRY_STRING("capstone"),
		DATA_SUSP_ENTRY_STRING("Cuckoo")
	};
	char * actual_addr = (char *)0;
	bool found_or_endmemory = false;
	bool exception_ex = false;
	* found = false;

	OutInfo("Searching suspicius data in my memory, this method is slow, be patient: ");

	// TODO: refactorize this bullshit..
	do 
	{	
		// TODO: a try - except for each data entry. Now if there is an exception in any data entry: i == 0 (and this is a little crap).
		for (int i = 0; i < ARRAYSIZE(suspicius_data); i++)
		{
			__try
			{
				if (actual_addr != suspicius_data[i].data && memcmp(suspicius_data[i].data, actual_addr, suspicius_data[i].size) == 0)
				{
					__try
					{
						if (memcmp(actual_addr + suspicius_data[i].size, SUSP_CTRL_STRING, sizeof(SUSP_CTRL_STRING)) != 0)
						{
							char buff[255];
							memset(buff, 0, sizeof(buff));
							__try
							{
								for (int j = 0; actual_addr[j] != 0 && j < sizeof(buff) - 1; j++)
								{
									buff[j] = actual_addr[j];
									if (!isprint(buff[j]))
										buff[j] = ' ';
								}
							}
							__except (filterExceptionExecuteHandler(GetExceptionCode(), GetExceptionInformation()))
							{
							}
							* found = true;
							OutInfo("\nSuspicius string found at: 0x%08X!: %.*s\n    Fragment found: %s", actual_addr, suspicius_data[i].size, suspicius_data[i].data, buff);
							Report("Suspicius_string_found_%.*s", suspicius_data[i].size, suspicius_data[i].data);
							memset(buff, 0, sizeof(buff));
							actual_addr += suspicius_data[i].size;
							exception_ex = true;
						}
					}
					__except (filterExceptionExecuteHandler(GetExceptionCode(), GetExceptionInformation()))
					{
					}
				}
			}
			__except (filterExceptionExecuteHandler(GetExceptionCode(), GetExceptionInformation())) 
			{
				exception_ex = true; 

				if ((DWORD)actual_addr >= ((DWORD)GetModuleHandleExW & 0xFFFFF000)) // TODO: Get better the end addr directly from PEB....
					found_or_endmemory = true;
				else
				{
					i = -1; // very dirty xD
					actual_addr += PAGE_SIZE;
					actual_addr = (char *)((DWORD)actual_addr & 0xFFFFF000);
					printf("\b\b\b\b\b\b\b\b\b\b0x%08X", actual_addr);
				}
			}
		}
		if (exception_ex == false)
			actual_addr++;
		exception_ex = false;
	} while (found_or_endmemory == false);
	OutInfo("");

	return 0;
}

int filterExceptionExecuteHandler(int code, PEXCEPTION_POINTERS ex)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

#define EXT_REPORT ".dtct"

void Report(char * format, ...)
{
	FILE * file;
	char file_name[MAX_PATH];
	va_list args;
	va_start(args, format);

	memset(file_name, 0, sizeof(file_name));
	vsprintf_s(file_name, sizeof(file_name), format, args);
	strcat_s(file_name, sizeof(file_name), EXT_REPORT);
	fopen_s(&file, file_name, "wb+");
	if (file != NULL)
	{
		fputs(file_name, file);
		fclose(file);
	}
	va_end(args);
}