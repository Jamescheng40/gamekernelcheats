#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>

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
	ULONG64 base_address;

}JCH_Options;

uintptr_t base_address = 0;
std::uint32_t process_id = 0;

template<typename ... Arg>
uint64_t call_hook(const Arg ... args)
{
	void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtQueryCompositionSurfaceStatistics");
	 
	auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hooked_func);

	return func(args ...);

}

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{

			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

std::uint32_t get_process_id(std::string_view process_name)
{
	PROCESSENTRY32 processentry;
	/*HANDLE test = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);*/

	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return NULL;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE)
	{
		if (process_name.compare(processentry.szExeFile) == NULL)
		{
			return processentry.th32ProcessID;
		
		}


	}

	return NULL; 
}

static ULONG64 get_module_base_address(const char* module_name)
{
	JCH_Options instruction = { 0 };
	instruction.pid = process_id;
	instruction.req_base = TRUE;
	instruction.read = FALSE;
	instruction.write = FALSE;
	instruction.module_name = module_name;
	call_hook(&instruction);

	ULONG64 base = NULL;
	base = instruction.base_address;
	return base;

}

template <class T>
T Read(UINT_PTR read_address)
{
	T response{};
	JCH_Options instruction;
	instruction.pid = process_id;
	instruction.size = sizeof(T);
	instruction.address = read_address;
	instruction.read = TRUE;
	instruction.write = FALSE;
	instruction.req_base = FALSE;
	instruction.output = &response;
	call_hook(&instruction);

	return response;

}

bool write_memory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
	JCH_Options instruction;
	instruction.address = write_address;
	instruction.pid = process_id;
	instruction.write = TRUE;
	instruction.read = FALSE;
	instruction.req_base = FALSE;
	instruction.buffer_address = (void*)source_address;
	instruction.size = write_size;

	call_hook(&instruction);

	return true;
}

template<typename S> 
bool write(UINT_PTR write_address, const S& value)
{
	return write_memory(write_address, (UINT_PTR)&value, sizeof(S));
}

int main()
{
	base_address = get_module_base_address("RainbowSix.exe");

	if (!base_address)
	{

		printf("failed to get base address");
	}
	else
	{
		printf("Yes");
	}

	Sleep(500);
	return NULL;
}