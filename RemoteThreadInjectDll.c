#include <tchar.h>
#include <Windows.h>

BOOL CurrentProcessAdjustToken(int);
void DisplayErrorMessage(LPTSTR pszMessage, DWORD dwLastError);

// usage: RemoteInjection [: pid] [: DllPath] [: optional[: mode(default 0 run as common user, or 1 run as administrator even system)]]
int wmain(int argc, wchar_t *argv[])
{
	if (argc < 3) {
		_putts(TEXT("usage: RemoteInjection [: pid] [: DllPath] [: optional[: mode(default 0 run as common user, or 1 run as administrator even system)]]\nexample: RemoteInjection.exe 512 C:\\test.dll\n         RemoteInjection.exe 512 C:\\test.dll 1"));
		return 0;
	} {
		int mode = 0;
		if (argc == 4 && _wtoi(argv[3]) != 0) {
			mode = 1;
		}
		if (!CurrentProcessAdjustToken(mode)) {
			_putts(TEXT("Privilege Adjust Failed"));
		}

		DWORD pid = 0;
		pid = _wtoi(argv[1]);
		if (pid <= 0) {
			_putts(TEXT("Invalid pid"));
			return 0;
		}

		HANDLE process = NULL;
		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (NULL == process)
		{
			DisplayErrorMessage((LPTSTR)"OpenProcess error: ", GetLastError());
			return 0;
		}
		
		const wchar_t* dllPath = argv[2];
		LPVOID mem = NULL;
		mem = VirtualAllocEx(process, NULL, wcslen(dllPath) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!mem) {
			_putts(TEXT("VirtualAllocEx error"));
			return 0;
		}

		if (!WriteProcessMemory(process, mem, dllPath, wcslen(dllPath) * sizeof(wchar_t), NULL)) {
			DisplayErrorMessage((LPTSTR)"WriteProcessMemory error: ", GetLastError());
			return 0;
		}

		HANDLE thread = NULL;
		thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, mem, 0, NULL);
		if (!thread) {
			_putts(TEXT("CreateRemoteThread error"));
			return 0;
		}

		WaitForSingleObject(thread, INFINITE);
		VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		CloseHandle(thread);
		CloseHandle(process);

		return 1;
	}
}

BOOL CurrentProcessAdjustToken(int mode) {
	if (mode == 0) {
		return FALSE;
	}
	HANDLE hToken;
	TOKEN_PRIVILEGES sTP;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid)) {
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL)) {
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}
	return FALSE;
}

void DisplayErrorMessage(LPTSTR pszMessage, DWORD dwLastError){
	HLOCAL hlErrorMessage = NULL;
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PTSTR)&hlErrorMessage, 0, NULL))
	{
		_tprintf(TEXT("%s: %s"), pszMessage, (PCTSTR)LocalLock(hlErrorMessage));
		LocalFree(hlErrorMessage);
	}
}
