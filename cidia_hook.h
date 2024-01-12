#pragma once
#include <Windows.h>
#include <vector>
#include <cstdio>
#include <tlhelp32.h>
#include <string>
#include <functional>

const char* _TCHAR(wchar_t* string)
{
    size_t len = wcslen(string) + 1;
    char* c_string = new char[len];
    size_t numCharsRead;
    wcstombs_s(&numCharsRead, c_string, len, string, _TRUNCATE);
    return c_string;
}

int GetProcessId(const char* pc)
{
    DWORD pid = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (std::string(_TCHAR(entry.szExeFile)).find(pc) != std::string::npos && pid == 0)
            {
                pid = entry.th32ProcessID;
            }
            else if (_TCHAR(entry.szExeFile) == pc)
            {
                pid = entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return pid;
}

struct _PROCESS_DATA
{
	HANDLE PROCESS_HANDLE;
	const char* PROCESS_NAME;
	int PROCESS_ID = 0;
};
//template <typename T>
class Process
{
private:
	_PROCESS_DATA M_PROCESS;
	const char* name;
public:
	Process(const char* process_name) : name(process_name) {}
    Process Open() {
        if (M_PROCESS.PROCESS_ID == 0)
            M_PROCESS.PROCESS_ID = GetProcessId(name);
        M_PROCESS.PROCESS_NAME = name;

        if (M_PROCESS.PROCESS_ID != 0)
            M_PROCESS.PROCESS_HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, M_PROCESS.PROCESS_ID);
        return Process(M_PROCESS.PROCESS_NAME);
	}
    uintptr_t GetModuleAddress(const char* moduleName)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, M_PROCESS.PROCESS_ID);

        if (snapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &moduleEntry)) {
            do {
                if (_TCHAR(moduleEntry.szModule) == moduleName) {
                    CloseHandle(snapshot);
                    return (uintptr_t)moduleEntry.modBaseAddr;
                }
            } while (Module32Next(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
        return 0;
    }
    HANDLE GetModule(const char* module)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, M_PROCESS.PROCESS_ID);

        if (snapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &moduleEntry)) {
            do {
                if (_TCHAR(moduleEntry.szModule) == module) {
                    CloseHandle(snapshot);
                    return moduleEntry.szModule;
                }
            } while (Module32Next(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
        return 0;
    }
    bool WriteMemory(const char* module, uintptr_t addr, LPCVOID buff) {
        void* address = (void*)((uintptr_t)GetModuleAddress(module) + addr);
        return WriteProcessMemory(M_PROCESS.PROCESS_HANDLE, (LPVOID)address, buff, sizeof(buff), 0);
    }
    template <typename T>
    T* ReadMemory(const char* module, uintptr_t addr, LPVOID buff, size_t* bytesRead_t = 0)
    {
        SIZE_T bytesRead;
        void* address = (void*)((uintptr_t)GetModuleAddress(module) + addr);
        if (ReadProcessMemory(M_PROCESS.PROCESS_HANDLE, (LPCVOID)address, buff, sizeof(buff), &bytesRead))
        {
            *bytesRead_t = bytesRead;
            return (T*)(buff);
        }
        else
        {
            return NULL;
        }
    }
    void Protect(const char* module, uintptr_t addr, SIZE_T sizeToProtect, DWORD OldProtect, std::function<void()> func = 0)
    {
        void* address = (void*)((uintptr_t)GetModuleAddress(module) + addr);

        VirtualProtectEx(M_PROCESS.PROCESS_HANDLE, (LPVOID)address, sizeToProtect, PAGE_EXECUTE_READWRITE, &OldProtect);
        func();
        VirtualProtectEx(M_PROCESS.PROCESS_HANDLE, (LPVOID)address, sizeToProtect, OldProtect, &OldProtect);

    }
    void SpoofAddress(const char* module, uintptr_t addr, LPCVOID newData)//spoof a address after inject
    {
        void* address = (void*)((uintptr_t)GetModuleAddress(module) + addr);
        LPVOID remoteMemory = VirtualAllocEx(M_PROCESS.PROCESS_HANDLE, (LPVOID)address, sizeof(newData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (remoteMemory == NULL)
        {
            CloseHandle(M_PROCESS.PROCESS_HANDLE);
        }
        else
        {
            WriteProcessMemory(M_PROCESS.PROCESS_HANDLE, remoteMemory, newData, sizeof(newData), NULL);
            VirtualFreeEx(M_PROCESS.PROCESS_HANDLE, remoteMemory, 0, MEM_RELEASE);
        }
    }
    void FreeLibrary(const char* module)
    {
        FARPROC pFreeLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");

        LPVOID pRemoteCode = VirtualAllocEx(M_PROCESS.PROCESS_HANDLE, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        SIZE_T bytesWritten;
        WriteProcessMemory(M_PROCESS.PROCESS_HANDLE, pRemoteCode, &pFreeLibrary, sizeof(pFreeLibrary), &bytesWritten);

        if (bytesWritten != sizeof(pFreeLibrary)) {
            VirtualFreeEx(M_PROCESS.PROCESS_HANDLE, pRemoteCode, 0, MEM_RELEASE);
            CloseHandle(M_PROCESS.PROCESS_HANDLE);
            return;
        }

        HANDLE hRemoteThread = CreateRemoteThread(M_PROCESS.PROCESS_HANDLE, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);

        if (hRemoteThread == NULL) {
            VirtualFreeEx(M_PROCESS.PROCESS_HANDLE, pRemoteCode, 0, MEM_RELEASE);
            CloseHandle(M_PROCESS.PROCESS_HANDLE);
            return;
        }

        WaitForSingleObject(hRemoteThread, INFINITE);

        CloseHandle(hRemoteThread);
        VirtualFreeEx(M_PROCESS.PROCESS_HANDLE, pRemoteCode, 0, MEM_RELEASE);

        void* thread = (void*)((uintptr_t)hRemoteThread);
        SpoofAddress(NULL, (uintptr_t)thread, 0x0);

    }
    int GetId()
    {
        return M_PROCESS.PROCESS_ID;
    }
    HANDLE GetHandle()
    {
        return M_PROCESS.PROCESS_HANDLE;
    }
    void Inject(LPCSTR dllPath)// inject a dll and spoof the Thread from the process´s anticheat
    {
        LPVOID baseAddress = VirtualAllocEx(M_PROCESS.PROCESS_HANDLE, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

        WriteProcessMemory(M_PROCESS.PROCESS_HANDLE, baseAddress, (LPCVOID)dllPath, strlen(dllPath) + 1, NULL);

        LPVOID loadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        HANDLE hLoadThread = CreateRemoteThread(M_PROCESS.PROCESS_HANDLE, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, baseAddress, 0, 0);
        void* thread = (void*)((uintptr_t)hLoadThread);
        //void* thread = (void*)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateRemoteThread"));
        WaitForSingleObject(hLoadThread, INFINITE);
        SpoofAddress(NULL, (uintptr_t)thread, 0x0);

    }
    void Close()
    {
        CloseHandle(M_PROCESS.PROCESS_HANDLE);
    }
};


