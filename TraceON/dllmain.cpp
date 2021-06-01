#include "pch.h"
#include <_plugins.h>   //basically like windows.h, includes all relevant header files
#include<malloc.h>
#include<ntdll.h>

template <typename PTR>

struct MYUNICODE_STRING
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        PTR dummy;
    };
    PTR _Buffer;
};

#include<mypeb.h>

#define PLUGIN_NAME "Trace...ON!"
#define PLUGIN_VERSION 1

typedef NTSTATUS(WINAPI* t_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* t_NtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
typedef DWORD64 PTR1;

typedef struct _PROCESS_BASIC_INFORMATION64
{
    DWORD ExitStatus;
    PTR1 PebBaseAddress;
    PTR1 AffinityMask;
    DWORD BasePriority;
    PTR1 UniqueProcessId;
    PTR1 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;

struct loadedDLLs
{

    void* BaseOfDLL;
    DWORD SizeOfDLL;
    struct loadedDLLs* Next;
};


int pluginHandle;
int DestAddr = 0;
duint prevcip;
struct loadedDLLs* Head = NULL;
HANDLE hDebugee;
PVOID64 DebugeePEB64 = NULL;
DWORD64 Wow64DLLBase, Wow64DLLSize;


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

BOOL GetSizeOfImage(DWORD ImageBase, DWORD* pImageSize)
{
    DWORD OffsetNTHeader, NumberOfBytesRead;
    BOOL status = ReadProcessMemory(hDebugee, (LPCVOID)(ImageBase + 0x3C), &OffsetNTHeader, 4, &NumberOfBytesRead);

    if (!status)
        return FALSE;

    PIMAGE_NT_HEADERS ImageNtHeader = (PIMAGE_NT_HEADERS)(ImageBase + OffsetNTHeader);

    status = ReadProcessMemory(hDebugee, (LPCVOID)(&(ImageNtHeader->OptionalHeader.SizeOfImage)), pImageSize, 4, &NumberOfBytesRead);

    if (!status)
        return FALSE;

    return TRUE;
}

static void cbDebugloop(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_DEBUGEVENT* d = (PLUG_CB_DEBUGEVENT*)callbackInfo;

    LPVOID DLLBase;
    DWORD PESize;

    switch (d->DebugEvent->dwDebugEventCode)
    {

    case CREATE_PROCESS_DEBUG_EVENT:
    {
        hDebugee = (d->DebugEvent->u.CreateProcessInfo).hProcess;
        struct loadedDLLs* NewNode = (struct loadedDLLs*)malloc(sizeof(struct loadedDLLs));
        DLLBase = (d->DebugEvent->u.CreateProcessInfo).lpBaseOfImage;

        NewNode->BaseOfDLL = DLLBase;

        if (GetSizeOfImage((DWORD)DLLBase, &PESize))
        {
            NewNode->SizeOfDLL = PESize;
        }

        if (Head == NULL)
        {
            Head = NewNode;
            //NewNode->Next = NULL;
        }

        else
        {
            struct loadedDLLs* prev = Head;

            while (prev->Next != NULL)
            {
                prev = prev->Next;
            }

            prev->Next = NewNode;
        }

        NewNode->Next = NULL;


        break;
    }

    case LOAD_DLL_DEBUG_EVENT:
    {
        struct loadedDLLs* NewNode = (struct loadedDLLs*)malloc(sizeof(struct loadedDLLs));

        //strcpy(NewNode->DLLName, (char*)(d->DebugEvent->u.LoadDll).lpImageName);

        //PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((d->DebugEvent->u.LoadDll).lpBaseOfDll);
        //DWORD DLLSize = ntHeaders->OptionalHeader.SizeOfImage;

        DLLBase = (d->DebugEvent->u.LoadDll).lpBaseOfDll;
        //NewNode->BaseOfDLL = (d->DebugEvent->u.LoadDll).lpBaseOfDll;
        NewNode->BaseOfDLL = DLLBase;

        if (GetSizeOfImage((DWORD)DLLBase, &PESize))
            NewNode->SizeOfDLL = PESize;

        if (Head == NULL)  ////add DLLBase to known modules list
        {
            Head = NewNode;
            //NewNode->Next = NULL;
        }

        else
        {
            struct loadedDLLs* prev = Head;

            while (prev->Next != NULL)
            {
                prev = prev->Next;
            }

            prev->Next = NewNode;
        }

        NewNode->Next = NULL;
    }

    }
}

__declspec(noinline) bool IsJmpAddressKnown(DWORD JmpAddy)
{
    struct loadedDLLs* Node = Head;

    while (Node != NULL)
    {
        if ((JmpAddy > (DWORD)(Node->BaseOfDLL)) && (JmpAddy < ((DWORD)(Node->BaseOfDLL) + Node->SizeOfDLL)))
        {
            return true;
        }
        Node = Node->Next;
    }

    return false;
}



static void Wow64DLLFinder(CBTYPE cbType, void* callbackInfo)
{
    t_NtWow64QueryInformationProcess64 _NtWow64QueryInformationProcess64 = NULL;
    PROCESS_BASIC_INFORMATION64 pbi = { 0 };
    PEB64 Wow64PEB = { 0 };
    PEB_LDR_DATA64 LdrData64 = { 0 };
    LDR_DATA_TABLE_ENTRY64 LdrHead = { 0 };
    ULONG outlength;

    _NtWow64QueryInformationProcess64 = (t_NtWow64QueryInformationProcess64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64QueryInformationProcess64");

    if (_NtWow64QueryInformationProcess64 != NULL)
    {

        NTSTATUS status1 = _NtWow64QueryInformationProcess64(hDebugee, ProcessBasicInformation, &pbi, sizeof(pbi), &outlength);

        if (status1 == STATUS_SUCCESS)
        {
            DebugeePEB64 = (PVOID64)pbi.PebBaseAddress;
            t_NtWow64ReadVirtualMemory64 _NtWow64ReadVirtualMemory64 = (t_NtWow64ReadVirtualMemory64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64ReadVirtualMemory64");

            NTSTATUS status2 = _NtWow64ReadVirtualMemory64(hDebugee, DebugeePEB64, &Wow64PEB, sizeof(Wow64PEB), nullptr);

            if (status2 == STATUS_SUCCESS)
            {
                NTSTATUS status3 = _NtWow64ReadVirtualMemory64(hDebugee, (PVOID64)Wow64PEB.Ldr, &LdrData64, sizeof(PEB_LDR_DATA64), nullptr);

                if (status3 == STATUS_SUCCESS)
                {
                    LdrHead.InLoadOrderLinks.Flink = LdrData64.InLoadOrderModuleList.Flink;
                    const ULONG64 LastEntry = Wow64PEB.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);

                    do
                    {
                        _NtWow64ReadVirtualMemory64(hDebugee, (PVOID64)LdrHead.InLoadOrderLinks.Flink, &LdrHead, sizeof(LDR_DATA_TABLE_ENTRY64), nullptr);

                        wchar_t* BaseDllName = (wchar_t*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, LdrHead.BaseDllName.MaximumLength);
                        _NtWow64ReadVirtualMemory64(hDebugee, (PVOID64)LdrHead.BaseDllName.Buffer, BaseDllName, LdrHead.BaseDllName.MaximumLength, nullptr);

                        Wow64DLLBase = LdrHead.DllBase;
                        Wow64DLLSize = LdrHead.SizeOfImage;

                        //if (_wcsicmp(L"wow64cpu.dll", BaseDllName) == 0)

                        if ((Wow64DLLBase >> 32) == 0) //checks if DLLBase is 32 bit, don't care about a 64 bit DLLBase as they're outside the simulated wow64 environment 
                        {
                            struct loadedDLLs* NewNode = (struct loadedDLLs*)malloc(sizeof(struct loadedDLLs));
                            NewNode->BaseOfDLL = (void*)Wow64DLLBase;
                            NewNode->SizeOfDLL = (DWORD)Wow64DLLSize;

                            if (Head == NULL)     //add DLLBase to known modules list
                            {
                                Head = NewNode;
                                //NewNode->Next = NULL;
                            }

                            else
                            {
                                struct loadedDLLs* prev = Head;

                                while (prev->Next != NULL)
                                {
                                    prev = prev->Next;
                                }

                                prev->Next = NewNode;
                            }

                            NewNode->Next = NULL;

                        }

                    } while (LdrHead.InLoadOrderLinks.Flink != LastEntry);
                }
            }
        }

    }



}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT * initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);
    _plugin_registercallback(pluginHandle, CB_SYSTEMBREAKPOINT, Wow64DLLFinder);
    return TRUE;
}

extern "C" __declspec(dllexport) void CBTRACEEXECUTE(CBTYPE cbType, PLUG_CB_TRACEEXECUTE * info)
{
    DISASM_INSTR disasm = { 0 };

    //The commented out block disassembles each instruction and tries to detect call/jump to an unknown memory region. Unfortunately slows down the plugin even more

    /*DbgDisasmAt(info->cip, &disasm);

    char* operation = strtok(disasm.instruction, " ");

    if (!strcmp(operation, "call" ))
    {
        //int DestAddr= (int)strtol(strtok(NULL, " "), NULL, 0);

        DestAddr = DbgGetBranchDestination(info->cip);

        if (!IsJmpAddressKnown(DestAddr))
            info->stop = true;
    }

    else if (!strcmp(operation, "jmp") || !strcmp(operation, "jne") || !strcmp(operation, "je") ||
             !strcmp(operation, "jc") || !strcmp(operation, "jnc") || !strcmp(operation, "jz") ||
             !strcmp(operation, "jnz"))
    {
        if (DbgIsJumpGoingToExecute(info->cip))
        {
             DestAddr = DbgGetBranchDestination(info->cip);

            if (!IsJmpAddressKnown(DestAddr))
                info->stop = true;
        }
    }
    */

    //simply checks if the instruction pointer is within unknown memory region

    if (!IsJmpAddressKnown(info->cip))
    {
        info->stop = true;
        _plugin_logprintf(R"(EIP before execution transfer was %p )", prevcip);
    }
    else
    {
        prevcip = info->cip;
    }
}

