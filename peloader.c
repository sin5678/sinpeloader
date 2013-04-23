/*
Copyright (C) sincoder

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#include <windows.h>
#include <tchar.h>
#include <winnt.h>
#include "PEB.h"
#include "Debug.h"
//PELoader.c

static INT ShowUsage()
{
    printf("Sin PE Loader\n");
    printf("PeLdr [PE-File]\n");
    return 0;
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
        DMSG("Relocation not required");
        return TRUE;
    }

    if(!pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        DMSG("PE required relocation but no relocatiom information found");
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
                DMSG("Unknown relocation type: 0x%08x", pReloc->type);
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

    DMSG("Process Export Table.");
    pDosHeader = (PIMAGE_DOS_HEADER)dwMapBase;
    pNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMapBase) + pDosHeader->e_lfanew);
    pExportTable=(PIMAGE_EXPORT_DIRECTORY)(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+dwMapBase);
    dwExportSize=pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if(dwExportSize == 0)
    {
        DMSG("Export Table Not found");
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

    DMSG("Processing IAT");

    do {
        pDosHeader = (PIMAGE_DOS_HEADER) dwMapBase;
        pNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMapBase) + pDosHeader->e_lfanew);
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dwMapBase +
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        if(!pImportDesc) {
            DMSG("IAT not found");
            break;
        }

        while((pImportDesc->Name != 0) && (!flError))
        {
            pLibName = (BYTE*) (dwMapBase + pImportDesc->Name);
            DMSG("Loading Library and processing Imports: %s", (CHAR*) pLibName);

            //  if(pImportDesc->ForwarderChain != -1) 
            // {
            //      DMSG("FIXME: Cannot handle Import Forwarding currently");
            ///      flError = 1;
            //     break;
            //  }

            hMod = LoadLibraryA((CHAR*) pLibName);
            if(!hMod) {
                DMSG("Failed to load library: %s", pLibName);
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
                        DMSG("Failed to resolve API: %s!%s", 
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
    wchar_t procBuff[64];

    hFile = CreateFile(pFile, GENERIC_READ, 
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        DMSG("Failed to open PE File");
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

    DMSG("Mapping PE File");

    pDosHeader = (PIMAGE_DOS_HEADER) dwImage;
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DMSG("DOS Signature invalid");
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

    DMSG("Current process base: 0x%08x", dwMyBase);

    DMSG("Target PE Load Base: 0x%08x Image Size: 0x%08x",
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
        DMSG("Try to load PE in same base address as the loader");
        DMSG("Let me  reloc it");
        if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            dwMapBase = (DWORD) VirtualAlloc(NULL, 
                pNtHeaders->OptionalHeader.SizeOfImage + 1,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        else
        {
            DMSG("Can not find the reloc table");
            DMSG("Let me reloc myself");
            pMyDosHeader = (PIMAGE_DOS_HEADER) dwMyBase;
            pMyNtHeaders = (PIMAGE_NT_HEADERS) (PIMAGE_NT_HEADERS)(((DWORD) dwMyBase) + pMyDosHeader->e_lfanew);
            dwMyNewBase = (DWORD)VirtualAlloc(NULL,pMyNtHeaders->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
            if(!dwMyNewBase)
            {
                EMSG("Alloc Memery Failed ..");
                goto out;
            }
            DMSG("My new base is %08x",dwMyNewBase);
            VirtualProtect((LPVOID)dwMyBase,pMyNtHeaders->OptionalHeader.SizeOfImage,PAGE_EXECUTE_READWRITE,&dwOldProtect);
            RtlCopyMemory((void *)dwMyNewBase,(void *)dwMyBase,pMyNtHeaders->OptionalHeader.SizeOfImage);
            ret = ProcessRelocations(dwMyNewBase);
            if(!ret)
            {
                DMSG("Reloc Myself Failed");
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
                EMSG("UnmapViewOfFile Failed .%d",GetLastError());
                goto out;
            }
            // dwMyBase = dwMyNewBase;
            DMSG("I have reloc myself!");
        }
    }
    if(!dwMapBase)
        dwMapBase = (DWORD) VirtualAlloc((LPVOID) pNtHeaders->OptionalHeader.ImageBase,pNtHeaders->OptionalHeader.SizeOfImage + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!dwMapBase)
    {
        if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            DMSG("Alloc memery failed,try to reloc it");
            dwMapBase = (DWORD) VirtualAlloc(NULL, 
                pNtHeaders->OptionalHeader.SizeOfImage + 1,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        else
            EMSG("Failed to allocate PE ImageBase: 0x%08x,No reloc infomation",pNtHeaders->OptionalHeader.ImageBase);
    }

    if(!dwMapBase) 
    {
        EMSG("Failed to map memory for Target PE");
        goto out;
    }
    DMSG("Allocated memory for Target PE: 0x%08x", dwMapBase);
    DMSG("Copying Headers");
    CopyMemory((LPVOID) dwMapBase, (LPVOID) dwImage,pNtHeaders->OptionalHeader.SizeOfHeaders);
    DMSG("Copying Sections");
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for(i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) 
    {
        DMSG("  Copying Section: %s", (CHAR*) pSectionHeader[i].Name);
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
    DMSG("Executing Entry Point: 0x%08x", dwEP);
    pOrgiCommandline = *(DWORD **)((BYTE *)GetCommandLineW+1);
    if(dwMyNewBase)
    {
        pCommandLine = (wchar_t *)(dwMyNewBase + (DWORD)pCommandLine - dwMyBase);
    }
    *pOrgiCommandline = (DWORD)pCommandLine;
    //判断是不是 dll
    if(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        DMSG("this file is a dll.");
        __asm
        {
            int 3
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

int wmain(int argc, wchar_t *argv[])
{
    if(argc < 2)
        return ShowUsage();
    LoadPE(argv[1],L"\"c:\\windows\\system32\\I am sincoder.exe\"");
    return 0;
}
