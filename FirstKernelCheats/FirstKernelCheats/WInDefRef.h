#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#pragma comment(lib, "ntoskrnl.lib")

#define WOW64_POINTER(Type) ULONG
//entry 32 req start symbols
 typedef enum _LDR_DLL_LOAD_REASON
 {
	     LoadReasonStaticDependency,
		     LoadReasonStaticForwarderDependency,
		     LoadReasonDynamicForwarderDependency,
		    LoadReasonDelayloadDependency,
		     LoadReasonDynamicLoad,
		     LoadReasonAsImageLoad,
		     LoadReasonAsDataLoad,
		     LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef struct _RTL_BALANCED_NODE32
{
	union
	{
		WOW64_POINTER(struct _RTL_BALANCED_NODE*) Children[2];
		struct
		{
			WOW64_POINTER(struct _RTL_BALANCED_NODE*) Left;
			WOW64_POINTER(struct _RTL_BALANCED_NODE*) Right;
		};
	};
	union
	{
		WOW64_POINTER(UCHAR) Red : 1;
		WOW64_POINTER(UCHAR) Balance : 2;
		WOW64_POINTER(ULONG_PTR) ParentValue;
	};
} RTL_BALANCED_NODE32, * PRTL_BALANCED_NODE32;

//entry 32
 typedef struct _LDR_DATA_TABLE_ENTRY32
 {
	     LIST_ENTRY32 InLoadOrderLinks;
	     LIST_ENTRY32 InMemoryOrderLinks;
	     union
		     {
		         LIST_ENTRY32 InInitializationOrderLinks;
		       LIST_ENTRY32 InProgressLinks;
		     };
	     WOW64_POINTER(PVOID) DllBase;
	     WOW64_POINTER(PVOID) EntryPoint;
	     ULONG SizeOfImage;
	     UNICODE_STRING32 FullDllName;
	     UNICODE_STRING32 BaseDllName;
	     union
		     {
		         UCHAR FlagGroup[4];
		         ULONG Flags;
		         struct
			         {
			            ULONG PackagedBinary : 1;
			            ULONG MarkedForRemoval : 1;
			             ULONG ImageDll : 1;
			            ULONG LoadNotificationsSent : 1;
			             ULONG TelemetryEntryProcessed : 1;
			             ULONG ProcessStaticImport : 1;
			             ULONG InLegacyLists : 1;
			             ULONG InIndexes : 1;
			           ULONG ShimDll : 1;
			             ULONG InExceptionTable : 1;
			           ULONG ReservedFlags1 : 2;
			             ULONG LoadInProgress : 1;
			            ULONG LoadConfigProcessed : 1;
			            ULONG EntryProcessed : 1;
			            ULONG ProtectDelayLoad : 1;
			           ULONG ReservedFlags3 : 2;
						ULONG DontCallForThreads : 1;
			             ULONG ProcessAttachCalled : 1;
			             ULONG ProcessAttachFailed : 1;
						ULONG CorDeferredValidate : 1;
			             ULONG CorImage : 1;
			             ULONG DontRelocate : 1;
			            ULONG CorILOnly : 1;
			            ULONG ReservedFlags5 : 3;
			             ULONG Redirected : 1;
			             ULONG ReservedFlags6 : 2;
			             ULONG CompatDatabaseProcessed : 1;
			        };
		     };
	     USHORT ObsoleteLoadCount;
	     USHORT TlsIndex;
	     LIST_ENTRY32 HashLinks;
	     ULONG TimeDateStamp;
	     WOW64_POINTER(struct _ACTIVATION_CONTEXT*) EntryPointActivationContext;
	     WOW64_POINTER(PVOID) Lock;
	    WOW64_POINTER(PLDR_DDAG_NODE) DdagNode;
	     LIST_ENTRY32 NodeModuleLink;
	     WOW64_POINTER(struct _LDRP_LOAD_CONTEXT*) LoadContext;
	     WOW64_POINTER(PVOID) ParentDllBase;
	    WOW64_POINTER(PVOID) SwitchBackContext;
	     RTL_BALANCED_NODE32 BaseAddressIndexNode;
	    RTL_BALANCED_NODE32 MappingInfoIndexNode;
	     WOW64_POINTER(ULONG_PTR) OriginalBase;
	     LARGE_INTEGER LoadTime;
	     ULONG BaseNameHashValue;
	    LDR_DLL_LOAD_REASON LoadReason;
	     ULONG ImplicitPathOptions;
	    ULONG ReferenceCount;
	} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
// entry 32 end

/* Abbreviated 32-bit PEB from dbghelp_private.h */
typedef struct _PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	DWORD   Mutant;
	DWORD   ImageBaseAddress;
	DWORD   LdrData;
	DWORD   ProcessParameters;
	DWORD   SubSystemData;
	DWORD   ProcessHeap;
	DWORD   FastPebLock;
	DWORD   FastPebLockRoutine;
	DWORD   FastPebUnlockRoutine;
	ULONG   EnvironmentUpdateCount;
	DWORD   KernelCallbackTable;
	ULONG   Reserved[2];
} PEB32;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
*PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

//typedef struct _RTL_PROCESS_MODULES
//{
//	ULONG NumberOfModules;
//	RTL_PROCESS_MODULE_INFORMATION Modules[1];
//} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


//for 64 bit process
typedef struct _PEB_LDR_DATA {
	ULONG length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

//32 bit process
typedef struct _PEB_LDR_DATA32
{
     ULONG Length;
     BOOLEAN Initialized;
     WOW64_POINTER(HANDLE) SsHandle;
	 LIST_ENTRY32 InLoadOrderModuleList;
	 LIST_ENTRY32 InMemoryOrderModuleList;
	 LIST_ENTRY32 InInitializationOrderModuleList;
	 WOW64_POINTER(PVOID) EntryInProgress;
	 BOOLEAN ShutdownInProgress;
	 WOW64_POINTER(HANDLE) ShutdownThreadId;
 } PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage; //in bytes 
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;


} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void);
//from reactOS
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9;

};

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

extern "C" __declspec(dllimport)
NTSTATUS NTAPI ZwProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG ProtectSize,
	ULONG NewProtect,
	PULONG OldProtect
);

extern "C" NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineNam
);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern "C" NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);

//32 bit process checker
extern "C" NTKERNELAPI
PVOID
PsGetProcessWow64Process(
	PEPROCESS Process
);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);


extern "C" BOOL NTAPI ReadProcessMemory
(   IN HANDLE 	hProcess,
	IN LPCVOID 	lpBaseAddress,
	IN LPVOID 	lpBuffer,
	IN SIZE_T 	nSize,
	OUT SIZE_T * lpNumberOfBytesRead
);