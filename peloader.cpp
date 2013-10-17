// Make sure WIN32_LEAN_AND_MEAN is defined
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#pragma comment(linker,"/BASE:0x300000")
#pragma comment(lib,"lde32.lib")
#define DMSG printf
#define BT_CALLAPI(api) ((P_##api)bt_GetApiPtrByName(#api))

typedef ULONG NTSTATUS;

typedef struct _STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

extern "C" int __stdcall LDE(void *, int);

typedef NTSTATUS (__stdcall *P_NtProtectVirtualMemory)(
												   __in HANDLE ProcessHandle,
												   __inout PVOID *BaseAddress,
												   __inout PSIZE_T RegionSize,
												   __in ULONG NewProtect,
												   __out PULONG OldProtect
												   );
typedef NTSTATUS (* P_LdrGetProcedureAddress) (
											   IN PVOID DllHandle,
											   IN PANSI_STRING ProcedureName OPTIONAL,
											   IN ULONG ProcedureNumber OPTIONAL,
											   OUT PVOID *ProcedureAddress
											   );

typedef struct _HookContext
{
    CHAR * ApiName;  //要 HOOK 的函数名字
    void * HookFunc; //HOOK 函数的地址  
    void * orig_func; //原函数的首地址
    DWORD  OpcodeLen; //复制的 opcode 的长度
    char   RealFunc[4 * 10]; //调回原函数的 头  40 个字节应该够了。。。
}HookContext;

typedef struct _ApiContext
{
    WCHAR *DllName; //所在 dll 的名字
    CHAR  *APiName; // API 的名字
    VOID  *FuncPtr; // 这个 API 的指针
}ApiContext;


// https://github.com/stephenfewer/ReflectiveDLLInjection
//===============================================================================================//
typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY
{
	//LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK * pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB // 65 elements, 0x210 bytes
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
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

extern BOOL ModifyCmdLine(DWORD dwPId, WCHAR *szData);

typedef struct
{
	WORD	offset:12;
	WORD	type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;


HookContext g_hook;

ApiContext g_ApiTable[]={
    // =---------  ntdll api
    {L"ntdll.dll","DbgPrint",NULL},
    {L"ntdll.dll","RtlCreateUserThread",NULL},
    {L"ntdll.dll","RtlAdjustPrivilege",NULL},
    {L"ntdll.dll","NtOpenProcess",NULL},
    {L"ntdll.dll","NtQuerySystemInformation",NULL},
    {L"ntdll.dll","RtlAllocateHeap",NULL},
    {L"ntdll.dll","NtDelayExecution",NULL},
    {L"ntdll.dll","RtlAnsiStringToUnicodeString",NULL},
    {L"ntdll.dll","LdrLoadDll",NULL},
    {L"ntdll.dll","RtlFreeHeap",NULL},
    {L"ntdll.dll","NtFreeVirtualMemory",NULL},
    {L"ntdll.dll","NtAllocateVirtualMemory",NULL},
    {L"ntdll.dll","NtWriteVirtualMemory",NULL},
    {L"ntdll.dll","NtProtectVirtualMemory",NULL},
    {L"ntdll.dll","NtCreateThread",NULL},
    {L"ntdll.dll","NtClose",NULL},
    {L"ntdll.dll","RtlInitAnsiString",NULL},
    {L"ntdll.dll","RtlFreeUnicodeString",NULL},
    {L"ntdll.dll","NtQueryInformationProcess",NULL},
    {L"ntdll.dll","RtlExitUserThread",NULL},
    {L"ntdll.dll","NtTerminateThread",NULL},
    {L"ntdll.dll","ZwDuplicateObject",NULL},
    {L"ntdll.dll","swprintf",NULL},
    {L"ntdll.dll","RtlGetVersion",NULL},
    {L"ntdll.dll","RtlInitUnicodeString",NULL},
    {L"ntdll.dll","LdrGetDllHandle",NULL},
    {L"ntdll.dll","NtResumeThread",NULL},
    {L"ntdll.dll","RtlRaiseStatus",NULL},
};

#if _MSC_VER < 1700

__declspec(naked) DWORD __readfsdword(DWORD _offset)
{
	__asm
	{
		push ebp
			mov ebp,esp
			mov ecx,_offset
			mov eax,dword ptr fs:[ecx]
			pop ebp
			retn 4
	}
}

#endif  /* _MSC_VER */
/*
根据 API 的名字 返回其函数地址
获取失败了 会抛出异常的  需要捕获下 
*/
LPVOID bt_GetApiPtrByName(CHAR *Name)
{
    LPVOID ptr = NULL;
    int idx = 0;
    for ( idx = 0; idx < sizeof(g_ApiTable)/sizeof(ApiContext); idx++)
    {
        if(strcmp(g_ApiTable[idx].APiName,Name) == 0)
        {
			if(g_ApiTable[idx].FuncPtr == NULL)
			{
				g_ApiTable[idx].FuncPtr = GetProcAddress(LoadLibraryW(g_ApiTable[idx].DllName),g_ApiTable[idx].APiName);
			}
            ptr = g_ApiTable[idx].FuncPtr;
            break;
        }
    }
    if(ptr == NULL)
    {
        //BT_CALLAPI(RtlRaiseStatus)(STATUS_NOT_FOUND);
    }
    return ptr;
}

__forceinline BOOL MakeMemWriteable(IN void *addr, IN int size)
{
    DWORD old_protect;
    SIZE_T MemSize = size;
    DWORD base = (DWORD )addr;
    return STATUS_SUCCESS == BT_CALLAPI(NtProtectVirtualMemory)((HANDLE)-1, 
        (void **)&base, 
        &MemSize, 
        PAGE_EXECUTE_READWRITE, 
        &old_protect);
}

// HOOK 下 loadlibrary
__forceinline DWORD bt_hook_getOpcodeLength(void *pAddress)
{
    return (DWORD)LDE(pAddress, 0);
}
/*
检查一个函数是不是被 HOOK 了 只检查第一个字节是不是 0xE9 也就是 jmp
*/
__forceinline BOOL bt_hook_IsFunctionHooked(void *  func)
{
    return 0xE9 == ((unsigned char *)func)[0];
}

/*
在 func1 的前五个字节改写成跳转到 fun2 的代码 
*/
BOOL bt_hook_Hook(HookContext *ctx)
{
    //先看看 func1 前面是不是有 5个 字节，，，，
    DWORD  OpcodeLen = 0;
    unsigned char *addr  = (unsigned char *)ctx->orig_func;
	
    //检测下 函数是不是已经被 HOOK 了。。
    if (bt_hook_IsFunctionHooked(ctx->orig_func))
    {
        return FALSE;
    }
    while(OpcodeLen < 5)
    {
	/*
	这里不检查 是不是 特别短的 函数  比如就一个指令  ret 
        */
        OpcodeLen += bt_hook_getOpcodeLength((void *)addr);
        addr = (unsigned char *)((DWORD)ctx->orig_func + OpcodeLen);
    }
	
    if(OpcodeLen > 40)
    {
        return FALSE;//应该是不可能的
    }
    // 然后 copy  OpcodeLen 长度的 代码 到一个我们动态分配的空间 \
    //ctx->Jmp_func = MyMalloc(OpcodeLen + 5);  //分配的内存直接就是 可读可写可执行的
	
    memcpy(ctx->RealFunc,ctx->orig_func,OpcodeLen);
	
    //再写入 5 个字节的 跳转 跳回 原函数
	
    *((unsigned char *)ctx->RealFunc + OpcodeLen)  = 0xE9;
	
    *(DWORD *)((unsigned char *)ctx->RealFunc + OpcodeLen + 1) =
        (DWORD)((unsigned char *)ctx->orig_func + OpcodeLen) - 
        (DWORD)((unsigned char *)ctx->RealFunc + OpcodeLen) - 5;
	
    if(!MakeMemWriteable(ctx->orig_func,OpcodeLen))
        goto _fail;
	
    //在原函数的 头部 写上 jmp ...
    *(unsigned char *)ctx->orig_func = 0xE9;
    *(DWORD *)((unsigned char *)ctx->orig_func + 1) = (DWORD)ctx->HookFunc - (DWORD)ctx->orig_func - 5;
	
    //如果 opcodelen > 5 那么 说明有多余的字节 此时写入 nop
	
    if(OpcodeLen > 5)
    {
        DWORD i = 0;
        for (; i < OpcodeLen - 5;i++)
        {
            ((unsigned char *)ctx->orig_func + 5 )[i] = 0x90;
        }
    }
	
    ctx->OpcodeLen = OpcodeLen;
    return TRUE;
_fail:
    //if(ctx->Jmp_func)
    //    MyFree(ctx->Jmp_func);
    return FALSE;
}

char * ConvertWCharToChar(const wchar_t * strOrigin,UINT uCodePage)
{
	int iSize;
	char *pBuffer;
	iSize = WideCharToMultiByte(uCodePage, 0, strOrigin, -1, NULL, 0, NULL, NULL); 
	if (!iSize)
	{
		return NULL;
	}
	pBuffer= (char *)malloc(iSize + 1);
	if (WideCharToMultiByte(uCodePage, 0, strOrigin, -1, pBuffer, iSize, NULL, NULL)==0)
	{
		free(pBuffer);
		return NULL;
	}
	return pBuffer;
}


WCHAR *Char2Wchar(const char *str)
{
    WCHAR *buff;
    int ret;
    ret = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, str, -1, NULL, 0);
    if(ret > 0)
    {
        buff = (WCHAR *)malloc(ret * sizeof(WCHAR));
        if(MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, str, -1, buff, ret))
            return buff;
        else
            free(buff);
    }
    return NULL;
}

BOOL ProcessRelocations(DWORD dwMapBase)
{
    UINT_PTR					iRelocOffset;
    DWORD						x;
    DWORD						dwTmp;
    PIMAGE_BASE_RELOCATION		pBaseReloc;
    PIMAGE_RELOC				pReloc;
    PIMAGE_DOS_HEADER           pDosHeader;
    PIMAGE_NT_HEADERS           pNtHeaders;
	
    pDosHeader = (PIMAGE_DOS_HEADER)dwMapBase;
    pNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMapBase) + pDosHeader->e_lfanew);
	
    if(dwMapBase == pNtHeaders->OptionalHeader.ImageBase) {
        return TRUE;
    }
	
    if(!pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        printf("PE required relocation but no relocatiom information found\n");
        return FALSE;
    }
	
    iRelocOffset = dwMapBase - pNtHeaders->OptionalHeader.ImageBase;
    pBaseReloc = (PIMAGE_BASE_RELOCATION) 
        (dwMapBase + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
    while(pBaseReloc->SizeOfBlock) {
        x = dwMapBase + pBaseReloc->VirtualAddress;
        dwTmp = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
        pReloc = (PIMAGE_RELOC) (((DWORD) pBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));
		
        while(dwTmp--) {
            switch(pReloc->type) {
            case IMAGE_REL_BASED_DIR64:
                *((UINT_PTR*)(x + pReloc->offset)) += iRelocOffset;
                break;	
            case IMAGE_REL_BASED_HIGHLOW:
                *((DWORD*)(x + pReloc->offset)) += (DWORD) iRelocOffset;
                break;
				
            case IMAGE_REL_BASED_HIGH:
                *((WORD*)(x + pReloc->offset)) += HIWORD(iRelocOffset);
                break;
				
            case IMAGE_REL_BASED_LOW:
                *((WORD*)(x + pReloc->offset)) += LOWORD(iRelocOffset);
                break;
				
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
				
            default:
                printf("Unknown relocation type: 0x%08x", pReloc->type);
                break;
            }
			
            pReloc += 1;
        }
		
        pBaseReloc = (PIMAGE_BASE_RELOCATION)(((DWORD) pBaseReloc) + pBaseReloc->SizeOfBlock);
    }
	
    return TRUE;
}

static BOOL ProcessEXT(DWORD dwMapBase)
{
    PIMAGE_DOS_HEADER           pDosHeader;
    PIMAGE_NT_HEADERS           pNtHeaders;
    WORD                        Index;
    PBYTE *                     pbAddressArray;
    PBYTE *                     pbSerialIndex;
    DWORD                       dwExportSize;
    PIMAGE_EXPORT_DIRECTORY     pExportTable;
	
    printf("Process Export Table.\n");
    pDosHeader = (PIMAGE_DOS_HEADER)dwMapBase;
    pNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMapBase) + pDosHeader->e_lfanew);
    pExportTable=(PIMAGE_EXPORT_DIRECTORY)(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+dwMapBase);
    dwExportSize=pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if(dwExportSize == 0)
    {
        printf("Export Table Not found\n");
        return TRUE;
    }
    if(NULL!=pExportTable)
    {
        pbAddressArray=(PBYTE*)(pExportTable->AddressOfFunctions+dwMapBase);
        pbSerialIndex=(PBYTE*)(pExportTable->AddressOfNameOrdinals+dwMapBase);
        for(Index=reinterpret_cast<WORD>(pbSerialIndex[0*2]);Index<pExportTable->NumberOfFunctions;Index++)
        {
            pbAddressArray[Index*1]=(pbAddressArray[Index*1]+(DWORD)dwMapBase);
        }
    }
    return TRUE;
}

static BOOL ProcessIAT(DWORD dwMapBase)
{
    BOOL						ret = FALSE;
    PIMAGE_IMPORT_DESCRIPTOR	pImportDesc;
    PIMAGE_THUNK_DATA			pThunkData;
    PIMAGE_THUNK_DATA			pThunkDataOrig;
    PIMAGE_IMPORT_BY_NAME		pImportByName;
    PIMAGE_EXPORT_DIRECTORY		pExportDir;
    DWORD						flError = 0;
    DWORD						dwTmp;
    BYTE						*pLibName;
    HMODULE						hMod;
    PIMAGE_DOS_HEADER           pDosHeader;
    PIMAGE_NT_HEADERS           pNtHeaders;
	
    DMSG("Processing IAT \n");
	
    do {
        pDosHeader = (PIMAGE_DOS_HEADER) dwMapBase;
        pNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMapBase) + pDosHeader->e_lfanew);
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dwMapBase +
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		
        if(!pImportDesc) {
            DMSG("IAT not found \n");
            break;
        }
		
        while((pImportDesc->Name != 0) && (!flError))
        {
            pLibName = (BYTE*) (dwMapBase + pImportDesc->Name);
            DMSG("Loading Library and processing Imports: %s\n", (CHAR*) pLibName);
			
            //  if(pImportDesc->ForwarderChain != -1) 
            // {
            //      DMSG("FIXME: Cannot handle Import Forwarding currently");
            ///      flError = 1;
            //     break;
            //  }
			
            hMod = LoadLibraryA((CHAR*) pLibName);
            if(!hMod) {
                DMSG("Failed to load library: %s\n", pLibName);
                flError = 1;
                break;
            }
			
            pThunkData = (PIMAGE_THUNK_DATA)(dwMapBase + pImportDesc->FirstThunk);
            if(pImportDesc->Characteristics == 0)
                /* Borland compilers doesn't produce Hint Table */
                pThunkDataOrig = pThunkData;
            else
                /* Hint Table */
                pThunkDataOrig = (PIMAGE_THUNK_DATA)(dwMapBase + pImportDesc->Characteristics);
			
            while(pThunkDataOrig->u1.AddressOfData != 0) 
            {
                if(pThunkDataOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
                {
                    /* Import via. Export Ordinal */
                    PIMAGE_DOS_HEADER		_dos;
                    PIMAGE_NT_HEADERS		_nt;
					
                    _dos = (PIMAGE_DOS_HEADER) hMod;
                    _nt = (PIMAGE_NT_HEADERS) (((DWORD) hMod) + _dos->e_lfanew);
					
                    pExportDir = (PIMAGE_EXPORT_DIRECTORY) 
                        (((DWORD) hMod) + _nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    dwTmp = (((DWORD) hMod) + pExportDir->AddressOfFunctions) + (((IMAGE_ORDINAL(pThunkDataOrig->u1.Ordinal) - pExportDir->Base)) * sizeof(DWORD));
                    dwTmp = ((DWORD) hMod) + *((DWORD*) dwTmp);
                    pThunkData->u1.Function = dwTmp;
                }
                else 
                {
                    pImportByName = (PIMAGE_IMPORT_BY_NAME)(dwMapBase + pThunkDataOrig->u1.AddressOfData);
                    pThunkData->u1.Function = (DWORD) GetProcAddress(hMod, (LPCSTR) pImportByName->Name);
					
                    if(!pThunkData->u1.Function)
                    {
                        DMSG("Failed to resolve API: %s!%s \n", 
                            (CHAR*)pLibName, (CHAR*)pImportByName->Name);
                        flError = 1;
                        break;
                    }
                }
				
                pThunkDataOrig++;
                pThunkData++;
            }
			
            pImportDesc++;
        }
		
        if(!flError)
            ret = TRUE;
		
    } while(0);
    return ret;
}
/*
loader 重定位
加载 DLL 

  */
  void LoadPE(wchar_t *pFile,wchar_t *pCommandLine)
  {
	  HANDLE	hFile = NULL;
	  HANDLE  hMap = NULL;
	  DWORD	dwSize;
	  DWORD	ret = 0;
	  DWORD   dwMapBase = 0;
	  DWORD   dwImage;
	  DWORD   dwMyBase = 0;
	  DWORD   dwMyNewBase = 0;
	  DWORD   dwOldProtect;
	  DWORD   i;
	  DWORD   dwEP;
	  DWORD*  pOrgiCommandline;
	  _PPEB   peb;
	  PIMAGE_DOS_HEADER pDosHeader;
	  PIMAGE_NT_HEADERS pNtHeaders;
	  PIMAGE_DOS_HEADER pMyDosHeader;
	  PIMAGE_NT_HEADERS pMyNtHeaders;
	  MEMORY_BASIC_INFORMATION	mi;
	  PIMAGE_SECTION_HEADER		pSectionHeader;
	  //    wchar_t procBuff[64];
	  
	  hFile = CreateFile(pFile, GENERIC_READ, 
		  FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	  if(hFile == INVALID_HANDLE_VALUE) {
		  DMSG("Failed to open PE File \n");
		  goto out;
	  }
	  hMap = CreateFileMappingW(hFile,NULL,PAGE_READONLY,0,0,NULL);
	  if(hMap == NULL)
	  {
		  DMSG("Failed to create maping,LastErr:%d",GetLastError());
		  goto out;
	  }
	  dwSize = GetFileSize(hFile, NULL);
	  dwImage = (DWORD)MapViewOfFile(hMap,FILE_MAP_READ,0,0,0);
	  if(NULL == dwImage)
	  {
		  DMSG("Failed to map view of the file,LastErr:%d",GetLastError());
		  goto out;
	  }
	  
	  DMSG("Mapping PE File\n");
	  
	  pDosHeader = (PIMAGE_DOS_HEADER) dwImage;
	  if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		  DMSG("DOS Signature invalid\n");
		  goto out;
	  }
	  
	  pNtHeaders = (PIMAGE_NT_HEADERS) 
		  (PIMAGE_NT_HEADERS)(((DWORD) dwImage) + pDosHeader->e_lfanew);
	  if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		  DMSG("NT Signature mismatch");
		  goto out;
	  }
	  
	  peb = (_PPEB)__readfsdword(0x30);
	  dwMyBase = (DWORD) peb->lpImageBaseAddress;
	  
	  DMSG("Current process base: 0x%08x \n", dwMyBase);
	  
	  DMSG("Target PE Load Base: 0x%08x Image Size: 0x%08x \n",
		  pNtHeaders->OptionalHeader.ImageBase,
		  pNtHeaders->OptionalHeader.SizeOfImage);
	  
	  // Find the size of our mapping
	  i = dwMyBase;
	  while(VirtualQuery((LPVOID) i, &mi, sizeof(mi))) 
	  {
		  if(mi.State == MEM_FREE)
			  break;
		  i += mi.RegionSize;
	  }
	  
	  if((pNtHeaders->OptionalHeader.ImageBase >= dwMyBase) && 
		  (pNtHeaders->OptionalHeader.ImageBase < i)) 
	  {
		  //先尝试重定位目标程序
		  DMSG("Try to load PE in same base address as the loader \n");
		  DMSG("Let me  reloc it \n");
		  if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		  {
			  dwMapBase = (DWORD) VirtualAlloc(NULL, 
				  pNtHeaders->OptionalHeader.SizeOfImage + 1,
				  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		  }
		  else
		  {
			  DMSG("Can not find the reloc table\n");
			  DMSG("Let me reloc myself\n");
			  pMyDosHeader = (PIMAGE_DOS_HEADER) dwMyBase;
			  pMyNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMyBase) + pMyDosHeader->e_lfanew);
			  dwMyNewBase = (DWORD)VirtualAlloc(NULL,pMyNtHeaders->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
			  if(!dwMyNewBase)
			  {
				  printf("Alloc Memery Failed ..\n");
				  goto out;
			  }
			  DMSG("My new base is %08x",dwMyNewBase);
			  VirtualProtect((LPVOID)dwMyBase,pMyNtHeaders->OptionalHeader.SizeOfImage,PAGE_EXECUTE_READWRITE,&dwOldProtect);
			  RtlCopyMemory((void *)dwMyNewBase,(void *)dwMyBase,pMyNtHeaders->OptionalHeader.SizeOfImage);
			  ret = ProcessRelocations(dwMyNewBase);
			  if(!ret)
			  {
				  DMSG("Reloc Myself Failed \n");
				  goto out;
			  }
			  __asm
			  {
				  push eax
					  mov eax,DWORD ptr cs:[ExitProcess]
					  mov [ebp+4],eax
					  call SIN
SIN:
				  pop eax
					  sub eax,dwMyBase
					  add eax,dwMyNewBase
					  add eax,12
					  jmp eax
					  pop eax
			  }
			  ret = UnmapViewOfFile((LPVOID)dwMyBase);
			  if(ret == 0)
			  {
				  printf("UnmapViewOfFile Failed .%d",GetLastError());
				  goto out;
			  }
			  // dwMyBase = dwMyNewBase;
			  printf("I have reloc myself! \n");
		  }
	  }
	  if(!dwMapBase)
		  dwMapBase = (DWORD) VirtualAlloc((LPVOID) pNtHeaders->OptionalHeader.ImageBase,pNtHeaders->OptionalHeader.SizeOfImage + 1,
		  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	  if(!dwMapBase)
	  {
		  if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		  {
			  DMSG("Alloc memery failed,try to reloc it \n");
			  dwMapBase = (DWORD) VirtualAlloc(NULL, 
				  pNtHeaders->OptionalHeader.SizeOfImage + 1,
				  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		  }
		  else
			  printf("Failed to allocate PE ImageBase: 0x%08x,No reloc infomation \n",pNtHeaders->OptionalHeader.ImageBase);
	  }
	  
	  if(!dwMapBase) 
	  {
		  printf("Failed to map memory for Target PE\n");
		  goto out;
	  }
	  DMSG("Allocated memory for Target PE: 0x%08x\n", dwMapBase);
	  DMSG("Copying Headers\n");
	  CopyMemory((LPVOID) dwMapBase, (LPVOID) dwImage,pNtHeaders->OptionalHeader.SizeOfHeaders);
	  DMSG("Copying Sections\n");
	  pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	  for(i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) 
	  {
		  CHAR sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
		  memcpy(sectionName,(CHAR*) pSectionHeader[i].Name,IMAGE_SIZEOF_SHORT_NAME);
		  sectionName[IMAGE_SIZEOF_SHORT_NAME] = 0;
		  DMSG("  Copying Section: %s\n", sectionName);
		  CopyMemory(
			  (LPVOID)(dwMapBase + pSectionHeader[i].VirtualAddress),
			  (LPVOID)(dwImage + pSectionHeader[i].PointerToRawData),
			  pSectionHeader[i].SizeOfRawData
			  );
	  }
	  //更新 pNtHeader 和 PDosHeader 的指针 使之指向新分配的内存
	  pDosHeader = (PIMAGE_DOS_HEADER) dwMapBase;
	  pNtHeaders = (PIMAGE_NT_HEADERS) 
		  (PIMAGE_NT_HEADERS)(((DWORD) dwMapBase) + pDosHeader->e_lfanew);
	  UnmapViewOfFile((LPVOID)dwImage);//关闭PE文件的内存映射
	  dwImage = NULL;
	  if(hFile)
		  CloseHandle(hFile);
	  hFile = NULL;
	  if(hMap)
		  CloseHandle(hMap);
	  hMap = NULL;
	  
	  ProcessIAT(dwMapBase);
	  ProcessEXT(dwMapBase); //输出表的加载无所谓
	  ProcessRelocations(dwMapBase);
	  dwEP = dwMapBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	  DMSG("Executing Entry Point: 0x%08x\n", dwEP);
      __asm int 3
	  pOrgiCommandline = *(DWORD **)((BYTE *)GetProcAddress(GetModuleHandleA("kernel32"),"GetCommandLineW")+1);  // windows 7 上不能这么搞
	  //if(dwMyNewBase)
	  //{
	  //	  pCommandLine = (wchar_t *)(dwMyNewBase + (DWORD)pCommandLine - dwMyBase);
	  //}
	  *pOrgiCommandline = (DWORD)wcsdup(pCommandLine);
	  //还要 patch 下 GetCommandLineA
	  pOrgiCommandline = *(DWORD **)((BYTE *)GetProcAddress(GetModuleHandleA("kernel32"),"GetCommandLineA")+1);  // windows 7 上不能这么搞
	  //if(dwMyNewBase)  命令行参数的地址放到堆中 就不需要重定位了
 	  //{
	  //	  pCommandLine = (CHAR *)(dwMyNewBase + (DWORD)pCommandLine - dwMyBase);
	  //}
	  *pOrgiCommandline = (DWORD)ConvertWCharToChar(pCommandLine,CP_ACP);

	  printf("cmdline is : %S \n",pCommandLine);
	  //ModifyCmdLine(GetCurrentProcessId(),pCommandLine);
	  printf("Let me jmp to the entrypoint !!\n");
	  //判断是不是 dll
	  if(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
	  {
		  DMSG("this file is a dll.\n");
		  __asm
		  {
			  //int 3
			  push 0 //Reserved
				  push 1 //DLL_PROCESS_ATTACH
				  mov  eax,dwMapBase
				  push eax
				  mov  eax,dwEP
				  call eax
		  }
		  // char name[] = "test";
		  // GetProcAddress((HMODULE)dwMapBase,name)(); //不能使用 GetProcAddress ，这个函数是根据加载的mod 来定位的
	  }
	  else
	  {
		  __asm 
		  {
			  mov eax,dword ptr fs:[0x18]//设置imagebase
				  mov eax,dword ptr ds:[eax+0x30]
				  mov ebx,dwMapBase
				  mov [eax+0x8],ebx
				  mov eax, dwEP
				  call eax
		  }
	  }
	  ExitProcess(-1);
out:
	  if(hFile)
		  CloseHandle(hFile);
	  if(hMap)
		  CloseHandle(hMap);
	  if(dwMyNewBase)
		  VirtualFree((LPVOID)dwMyNewBase,0,MEM_RELEASE);
}

//返回的 CHAR 要以 av_Free 释放掉 
CHAR *AnsiStringToChar(PANSI_STRING string)
{
    CHAR *str = NULL;
	str = (CHAR *)malloc(string->Length + sizeof(CHAR));
	strncpy(str, string->Buffer, string->Length); 
	str[string->Length] = 0; // wcsncpy 不会在后面补上  0
    return str;
}

PVOID __stdcall My_EncodePointer(IN PVOID Pointer	)
{
    ULONG Cookie = 0xd1ed;
    return (PVOID)((ULONG_PTR)Pointer ^ Cookie);
}

PVOID __stdcall My_DecodePointer(
								 PVOID Ptr
								 )
{
	ULONG Cookie = 0xd1ed;
    return (PVOID)((ULONG_PTR)Ptr ^ Cookie);
}

NTSTATUS HOOK_LdrGetProcedureAddress (
									  IN PVOID DllHandle,
									  IN PANSI_STRING ProcedureName OPTIONAL,
									  IN ULONG ProcedureNumber OPTIONAL,
									  OUT PVOID *ProcedureAddress
									  )
{
	//DBG_BRK();
    //看看是不是运行时加载的 。。。
    //if(FALSE == av_IsProcessStarting(NtCurrentProcess()))  运行到这里 必须是在 R3 了 ， 这个函数只适合探测其他进程
    {
        //获取模块名 还有 函数名称  以序号加载的 是 # 开头 比如 #5
        CHAR *procName = NULL;
        if(ProcedureName)
        {
            procName = AnsiStringToChar(ProcedureName);
        }
        else
        {
		/*
		int size = 64;
		procName = (CHAR *)av_Allocate(size);
		_snprintf(procName,size-1,"#%u",ProcedureNumber);
			*/
		}
		
        if(procName)
        {
			NTSTATUS status;
			//printf("get proc : %s \n",procName);
			status = ((P_LdrGetProcedureAddress)(void *)g_hook.RealFunc)(DllHandle,
				ProcedureName,
				ProcedureNumber,
				ProcedureAddress);
			if(STATUS_SUCCESS != status)
			{
				//printf("get proc : %s Failed \n",procName);
				//getchar();
				if(strcmp(procName,"RtlEncodePointer") == 0)
				{
					*ProcedureAddress = My_EncodePointer;
					status = STATUS_SUCCESS;
				}
				else if(strcmp(procName,"EncodePointer") == 0)
				{
					*ProcedureAddress = My_EncodePointer;
					status = STATUS_SUCCESS;
				}
				else if(strcmp(procName,"RtlDecodePointer") == 0)
				{
					*ProcedureAddress = My_DecodePointer;
					status = STATUS_SUCCESS;
				}
				else if(strcmp(procName,"DecodePointer") == 0)
				{
					*ProcedureAddress = My_DecodePointer;
					status = STATUS_SUCCESS;
				}
			}
			free(procName);
			return status;
        }
    }
    //return LdrpGetProcedureAddress(DllHandle,ProcedureName,ProcedureNumber,ProcedureAddress,TRUE);
    //............. 对加载不成功的也要记录下 
    return ((P_LdrGetProcedureAddress)(void *)g_hook.RealFunc)(DllHandle,
        ProcedureName,
        ProcedureNumber,
        ProcedureAddress);
}

WCHAR *SkipFirstCmd()
{
	WCHAR *next = NULL;
	WCHAR *cmd = GetCommandLineW();
	if(*cmd == L'\"')
	{
		next = cmd;
		next ++;
		while(next)
		{
			next = wcschr(next,L'\"');
			if(next && *(next - 1) != L'\\')
			{
				next++;
				break;
			}
			else if(next)
			{
				next++;
			}
		}
	}
	else 
	{
		next = wcschr(cmd,L' ');
	}
	if(NULL == next)
		return NULL;
	//下面跳过空格
	while(*next == L' ')
		next++;
	if(wcslen(next) < 1)
		next = NULL;
	return next;
}

int __cdecl wmain(int argc, WCHAR* argv[])
{
	g_hook.ApiName = "LdrGetProcedureAddress";
	g_hook.HookFunc = HOOK_LdrGetProcedureAddress;
	g_hook.orig_func = GetProcAddress(GetModuleHandleA("ntdll.dll"),"LdrGetProcedureAddress");
	g_hook.OpcodeLen = 0;
	
	bt_hook_Hook(&g_hook);
	
	WCHAR *cmd = SkipFirstCmd();
	if(NULL == cmd)
		cmd = argv[1];
	LoadPE(argv[1],cmd);
	Sleep(10000);
	return 0;
}
