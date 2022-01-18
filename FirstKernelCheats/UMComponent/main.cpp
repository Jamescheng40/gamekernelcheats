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
	PVOID base_address;
	BOOLEAN IsProc64bit;
	ULONG base_address32;
}JCH_Options;

PVOID base_address = 0;
std::uint32_t process_id = 0;

template<typename ... A>
uint64_t call_hook(const A ... args)
{
	//need to investigate how they found out this shit article posted on discord
	LoadLibrary("user32.dll");

	void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtDxgkGetTrackedWorkloadStatistics");
	 
	using tFunction = uint64_t(__stdcall*)(A ...);

	const auto control = static_cast<tFunction>(hooked_func);

	//auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hooked_func);

	//const auto control = static_cast<tFunction>(hooked_func);

	return control(args ...);

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

static PVOID get_module_base_address(const char* module_name, BOOLEAN IsProc64Bit)
{
	JCH_Options instruction = { 0 };
	instruction.pid = get_process_id(module_name);
	instruction.req_base = TRUE;
	instruction.read = FALSE;
	instruction.write = FALSE;
	instruction.module_name = module_name;
	instruction.IsProc64bit = IsProc64Bit;
	call_hook(&instruction);

	PVOID base = NULL;
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
	base_address = get_module_base_address("notepad.exe", TRUE);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base_address;
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