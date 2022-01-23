#pragma once
#include "WInDefRef.h"

PVOID get_module_base_x32(PEPROCESS proc, UNICODE_STRING module_name, HANDLE pid);
PVOID get_system_module_base(const char* module_name);
PVOID get_system_module_export(PCWSTR module_name, LPCSTR routine_name);
bool write_memory(void* address, void* buffer, size_t size);
bool write_to_read_only_memory(void* address, void* buffer, size_t size);
PVOID get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name);
bool read_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
bool write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
PVOID get_system_routine_address(PCWSTR routine_name);

typedef struct _JCH_Options_
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	void* output;
	const char* module_name;
	PVOID base_address;
	BOOLEAN IsProc64bit;
}JCH_Options;