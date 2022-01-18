#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#pragma comment(lib, "ntoskrnl.lib")

#define WOW64_POINTER(Type) ULONG

#define GDI_HANDLE_BUFFER_SIZE32   34
typedef ULONG 	GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
#define FLS_MAXIMUM_AVAILABLE 128
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
//typedef struct _PEB32
//{
//	BOOLEAN InheritedAddressSpace;
//	BOOLEAN ReadImageFileExecOptions;
//	BOOLEAN BeingDebugged;
//	BOOLEAN SpareBool;
//	DWORD   Mutant;
//	DWORD   ImageBaseAddress;
//	DWORD   LdrData;
//	DWORD   ProcessParameters;
//	DWORD   SubSystemData;
//	DWORD   ProcessHeap;
//	DWORD   FastPebLock;
//	DWORD   FastPebLockRoutine;
//	DWORD   FastPebUnlockRoutine;
//	ULONG   EnvironmentUpdateCount;
//	DWORD   KernelCallbackTable;
//	ULONG   Reserved[2];
//} PEB32;


 //peb32 full version 32 bit
 typedef struct _PEB32
 {
	     BOOLEAN InheritedAddressSpace;
	     BOOLEAN ReadImageFileExecOptions;
	     BOOLEAN BeingDebugged;
	     union
		     {
		         BOOLEAN BitField;
		         struct
			         {
			             BOOLEAN ImageUsesLargePages : 1;
			             BOOLEAN IsProtectedProcess : 1;
			             BOOLEAN IsLegacyProcess : 1;
			             BOOLEAN IsImageDynamicallyRelocated : 1;
			             BOOLEAN SkipPatchingUser32Forwarders : 1;
			             BOOLEAN IsPackagedProcess : 1;
			             BOOLEAN IsAppContainer : 1;
			             BOOLEAN SpareBits : 1;
			         };
		     };
	     WOW64_POINTER(HANDLE) Mutant;
	
		     WOW64_POINTER(PVOID) ImageBaseAddress;
	     WOW64_POINTER(PPEB_LDR_DATA) Ldr;
	     WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
	     WOW64_POINTER(PVOID) SubSystemData;
	     WOW64_POINTER(PVOID) ProcessHeap;
	     WOW64_POINTER(PRTL_CRITICAL_SECTION) FastPebLock;
	     WOW64_POINTER(PVOID) AtlThunkSListPtr;
	     WOW64_POINTER(PVOID) IFEOKey;
	     union
		     {
		         ULONG CrossProcessFlags;
		         struct
			         {
			             ULONG ProcessInJob : 1;
			             ULONG ProcessInitializing : 1;
			             ULONG ProcessUsingVEH : 1;
			             ULONG ProcessUsingVCH : 1;
			             ULONG ProcessUsingFTH : 1;
			             ULONG ReservedBits0 : 27;
			         };
		         ULONG EnvironmentUpdateCount;
		     };
	     union
		     {
		         WOW64_POINTER(PVOID) KernelCallbackTable;
		         WOW64_POINTER(PVOID) UserSharedInfoPtr;
		     };
	     ULONG SystemReserved[1];
	     ULONG AtlThunkSListPtr32;
	     WOW64_POINTER(PVOID) ApiSetMap;
	     ULONG TlsExpansionCounter;
	     WOW64_POINTER(PVOID) TlsBitmap;
	     ULONG TlsBitmapBits[2];
	     WOW64_POINTER(PVOID) ReadOnlySharedMemoryBase;
	     WOW64_POINTER(PVOID) HotpatchInformation;
	     WOW64_POINTER(PVOID*) ReadOnlyStaticServerData;
	     WOW64_POINTER(PVOID) AnsiCodePageData;
	     WOW64_POINTER(PVOID) OemCodePageData;
	     WOW64_POINTER(PVOID) UnicodeCaseTableData;
	
		     ULONG NumberOfProcessors;
	     ULONG NtGlobalFlag;
	
		     LARGE_INTEGER CriticalSectionTimeout;
	     WOW64_POINTER(SIZE_T) HeapSegmentReserve;
	     WOW64_POINTER(SIZE_T) HeapSegmentCommit;
	     WOW64_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
	     WOW64_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;
	
		     ULONG NumberOfHeaps;
	     ULONG MaximumNumberOfHeaps;
	     WOW64_POINTER(PVOID*) ProcessHeaps;
	
		     WOW64_POINTER(PVOID) GdiSharedHandleTable;
	     WOW64_POINTER(PVOID) ProcessStarterHelper;
	     ULONG GdiDCAttributeList;
	
		     WOW64_POINTER(PRTL_CRITICAL_SECTION) LoaderLock;
	
		     ULONG OSMajorVersion;
	     ULONG OSMinorVersion;
	     USHORT OSBuildNumber;
	     USHORT OSCSDVersion;
	     ULONG OSPlatformId;
	     ULONG ImageSubsystem;
	     ULONG ImageSubsystemMajorVersion;
	     ULONG ImageSubsystemMinorVersion;
	     WOW64_POINTER(ULONG_PTR) ImageProcessAffinityMask;
	     GDI_HANDLE_BUFFER32 GdiHandleBuffer;
	     WOW64_POINTER(PVOID) PostProcessInitRoutine;
	
		     WOW64_POINTER(PVOID) TlsExpansionBitmap;
	     ULONG TlsExpansionBitmapBits[32];
	
		     ULONG SessionId;
	
		     ULARGE_INTEGER AppCompatFlags;
	     ULARGE_INTEGER AppCompatFlagsUser;
	     WOW64_POINTER(PVOID) pShimData;
	     WOW64_POINTER(PVOID) AppCompatInfo;
	
		     UNICODE_STRING32 CSDVersion;
	
		     WOW64_POINTER(PVOID) ActivationContextData;
	     WOW64_POINTER(PVOID) ProcessAssemblyStorageMap;
	     WOW64_POINTER(PVOID) SystemDefaultActivationContextData;
	     WOW64_POINTER(PVOID) SystemAssemblyStorageMap;
	
		     WOW64_POINTER(SIZE_T) MinimumStackCommit;

		     WOW64_POINTER(PVOID*) FlsCallback;
	     LIST_ENTRY32 FlsListHead;
	     WOW64_POINTER(PVOID) FlsBitmap;
	     ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	     ULONG FlsHighIndex;
	
	     WOW64_POINTER(PVOID) WerRegistrationData;
	     WOW64_POINTER(PVOID) WerShipAssertPtr;
	     WOW64_POINTER(PVOID) pContextData;
	     WOW64_POINTER(PVOID) pImageHeaderHash;
	     union
		     {
		         ULONG TracingFlags;
		         struct
			         {
			             ULONG HeapTracingEnabled : 1;
			             ULONG CritSecTracingEnabled : 1;
			             ULONG LibLoaderTracingEnabled : 1;
			             ULONG SpareTracingBits : 29;
			         };
	     };
	     ULONGLONG CsrServerReadOnlySharedMemoryBase;
	 } PEB32, * PPEB32;



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


//for 64 bit process  this gets included because this instructure is buried under hidden modules
//typedef struct _PEB_LDR_DATA {
//	ULONG length;
//	BOOLEAN Initialized;
//	PVOID SsHandle;
//	LIST_ENTRY ModuleListLoadOrder;
//	LIST_ENTRY ModuleListMemoryOrder;
//	LIST_ENTRY ModuleListInitOrder;
//
//} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
#if (NTDDI_VERSION >= NTDDI_WIN7)
	UCHAR ShutdownInProgress;
	PVOID ShutdownThreadId;
#endif
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//32 bit process already defined in nt
//typedef struct _LIST_ENTRY32
//{
//	ULONG Flink, Blink;
//} LIST_ENTRY32, * PLIST_ENTRY32;

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
//from reactOS this is outdate check the following one out
//typedef struct _PEB {
//	BYTE Reserved1[2];
//	BYTE BeingDebugged;
//	BYTE Reserved2[1];
//	PVOID Reserved3[2];
//	PPEB_LDR_DATA Ldr;
//	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
//	PVOID Reserved4[3];
//	PVOID AtlThunkSListPtr;
//	PVOID Reserved5;
//	ULONG Reserved6;
//	PVOID Reserved7;
//	ULONG Reserved8;
//	ULONG AtlThunkSListPtr32;
//	PVOID Reserved9;
//
//};

//complete PEB structure
typedef struct _RTL_CRITICAL_SECTION* PRTL_CRITICAL_SECTION;
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK* pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;
typedef struct _PEB // 65 elements, 0x210 bytes
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	PPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STRING usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
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