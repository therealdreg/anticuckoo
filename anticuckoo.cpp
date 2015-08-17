#include "stdafx.h"
#include "anticuckoo.h"
#include "poc_exe.h"

// TODO: make more .cpp and .h files for all this...

int AntiCuckoo(int argc, _TCHAR* argv[])
{
	verbose = false;
	bool found;

	OutInfo(
		"Anticukoo %s\n"
		"By David Reguera Garcia aka Dreg - Dreg@fr33project.org\n"
		"http://www.fr33project.org/\n"
		"\n"
		"Crash parameters:\n"
		"    -c1: Crashing modifying RET instruction\n"
		"    -c2: Crashing when detects unhk thread\n"
		"-\n"
		, 
		VERSION_STRING_EXTENDED
	);

	if (argc == 2)
	{
		if (_tcscmp(argv[1], TEXT("-c1")) == 0)
			return StackRetCrash();

		if (_tcscmp(argv[1], TEXT("-c2")) == 0)
			return UnhkThreadCrash();
	}

	OutInfo("Detecting cuckoo...");

	//TODO: make a table here
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

DWORD WINAPI RunCreatePocExeThread(void * data)
{
	ResumeThread(*((HANDLE*)data));

	return 0;
}

int UnhkThreadCrash(void)
{
	// TODO: refactor this bullshit, and add more checks.
	OutInfo("Crashing when detects unhk thread");
	
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	HANDLE file;
	DWORD bytes_written;
	vector <DWORD> tids;

	system("taskkill /F /im poc.exe 2> NUL");
	DeleteFile(TEXT("poc.exe"));
	file = CreateFile(
		TEXT("poc.exe"),
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);

	if (file == INVALID_HANDLE_VALUE)
	{
		Error("CreateFile");
		return -1;
	}

	if (
		WriteFile(
			file, 
			exe_poc,
			sizeof(exe_poc),
			&bytes_written,
			NULL
		)
		== 
		0
		)
	{
		Error("WriteFile");
		return -1;
	}

	if (bytes_written != sizeof(exe_poc))
	{
		Error("bytes_written error");
		return -1;
	}

	FlushFileBuffers(file);
	CloseHandle(file);

	if (
		CreateProcess(
		TEXT("poc.exe"),
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi
		)
		==
		0
		)
	{
		return -1;
	}
	
	RunCreatePocExeThread(&(pi.hThread));
	
	int i = 0;
	OutInfo("Detecting new TIDs in the remote single thread process, wait aprox 60 seconds!");
	do
	{ 
		HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pi.dwProcessId);
		if (snapshot_handle != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 thread_entry;
			thread_entry.dwSize = sizeof(thread_entry);
			if (Thread32First(snapshot_handle, &thread_entry))
			{
				do
				{
					if (thread_entry.th32OwnerProcessID == pi.dwProcessId)
					{
						if (find(tids.begin(), tids.end(), thread_entry.th32ThreadID) == tids.end())
						{
							tids.push_back(thread_entry.th32ThreadID);
							OutInfo("\nNew TID detected!: 0x%X", thread_entry.th32ThreadID);
						}

						if (tids.size() > 2)
						{
							OutInfo("New threads in a single thread process! maybe a unhk thread detector, Crashing...\n");
							fflush(stdout);
							// very ugly cast here: 
							((void(*)(void))NULL)();
						}
					}
				} while (Thread32Next(snapshot_handle, &thread_entry));
			}

			CloseHandle(snapshot_handle);
		}
		printf(".");
		Sleep(1000);
	} while (i++ < 60);

	TerminateProcess(pi.hProcess, 0);
	DeleteFile(TEXT("poc.exe"));

	OutInfo("\nCongratz! NOT CUCKOOMON HERE!!");

	return 0;
}

#define STACK_RET_CRASH_API_NAME "DeleteFileA"
#define STACK_RET_CRASH_API_RET_VALUE 0x04

#define STACK_RET_CRASH_NEW_RET_VALUE 0x40

int StackRetCrash(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;
	char instruction_out[MAX_PATH];
	void * api = (void *)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), STACK_RET_CRASH_API_NAME);

	if (api == NULL)
	{
		api = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), STACK_RET_CRASH_API_NAME);
		if (api == NULL)
		{
			Error("Get API address: %s", STACK_RET_CRASH_API_NAME);
			return -1;
		}
	}
	void * addr_to_call = (void*)api;

	OutInfo("Crashing modifying RET instruction in: %s", STACK_RET_CRASH_API_NAME);
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return -1;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	
	// TODO: refactorize this crap.. (I know, I know, a lot of this kind comments xD)
	do
	{
		count = cs_disasm(handle, (const uint8_t *)api, 20, (uint64_t)api, 1, &insn);
		if (count == 1)
		{
			GetInstructionOut(instruction_out, sizeof(instruction_out), insn);
			OutInfo("%s", instruction_out);

			api = (void *)((char *)api + insn->size);
			if (insn->size == 3 && insn->bytes[0] == 0xC2 && insn->bytes[1] == STACK_RET_CRASH_API_RET_VALUE && insn->bytes[2] == 0x00)
			{
				DWORD old_protect;
				OutInfo("ret 0x%02X detected at: 0x%08X! changing page rights...", STACK_RET_CRASH_API_RET_VALUE, (DWORD)insn->address);
				if (!VirtualProtect((LPVOID)insn->address, 3, PAGE_EXECUTE_READWRITE, &old_protect))
				{
					Error("VirtualProtect");
					return -1; // TODO: fix cs_ mem leaks...
				}
				OutInfo("Writing 0x%02X value in ret instruction...", STACK_RET_CRASH_NEW_RET_VALUE);
				((unsigned char *)insn->address)[1] = STACK_RET_CRASH_NEW_RET_VALUE;
				OutInfo("Disasembling new ret instruction:");
				count = cs_disasm(handle, (const uint8_t *)insn->address, insn->size, (uint64_t)insn->address, 1, &insn);
				if (count == 1)
				{
					GetInstructionOut(instruction_out, sizeof(instruction_out), insn);
					OutInfo("%s", instruction_out);
					if (insn->size == 3 && insn->bytes[0] == 0xC2 && insn->bytes[1] == STACK_RET_CRASH_NEW_RET_VALUE && insn->bytes[2] == 0x00)
					{
						DWORD new_protect;
						OutInfo("New ret instruction is OK!");
						OutInfo("Restoring old page rights...");
						if (!VirtualProtect((LPVOID)insn->address, 3, old_protect, &new_protect))
							Error("VirtualProtect old rights");

						OutInfo("Crashing, if %s - 0x%08X is hooked and called from other handler", STACK_RET_CRASH_API_NAME, addr_to_call);
						OutInfo("Pushing %d DWORDs and calling to API...", STACK_RET_CRASH_NEW_RET_VALUE / 4);
						for (int x = 0; x < STACK_RET_CRASH_NEW_RET_VALUE; x += 4)
						{
							__asm 
							{ 
								push 0; 
							}
						}

						__asm 
						{
							call addr_to_call; 
						}

						OutInfo("Congratz! NOT CUCKOOMON HERE!!");

						//TODO: restore orig instruction (possible problems ex C runtime calls to modifyied API etc...)

						return 0;
					}
					else
					{
						Error("Bad new instruction!");
						return -1;
					}
				}
				else
				{
					Error("Disasembling new ret instruction");
					return -1;
				}
			}
			cs_free(insn, count); 
		}
		else
		{
			Error("Failed to disassemble given code!\n");
			return -1;
		}
	} while (1);

	cs_close(&handle);

	return 0;
}

int GetInstructionOut(char * out_str, size_t out_str_size, cs_insn *insn)
{
	char HEX_BYTE[3];

	memset(out_str, 0, out_str_size);
	sprintf_s(out_str, out_str_size, "0x%08X: %s %s | 0x", (DWORD)insn->address, insn->mnemonic, insn->op_str);
	for (int i = 0; i < insn->size; i++)
	{
		memset(HEX_BYTE, 0, sizeof(HEX_BYTE));
		sprintf_s(HEX_BYTE, sizeof(HEX_BYTE), "%02X", insn->bytes[i]);
		strcat_s(out_str, out_str_size, HEX_BYTE);
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
	//TODO: make a table here
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
