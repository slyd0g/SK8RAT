#ifndef HELPER_H
#define HELPER_H
#include <windows.h>
#include <string>
#include <sstream>
#include <random>

// Attempt to enable a specific SE Privilege (taken from throwback)
static DWORD EnablePrivilege(LPCTSTR name, HANDLE &hToken) {
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if (!LookupPrivilegeValue(NULL, name, &luid))
		return FALSE;

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		int t = GetLastError();
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

std::string ConvertToString(DWORD value) //or just use std::to_string
{
	std::stringstream ss;
	ss << value;
	return ss.str();
}

std::wstring GetUTF16(const std::string& str, int codepage)
{
	if (str.empty()) return std::wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
	std::wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
	return res;
}

//0 for file, 1 for dir, 2 for wtf
DWORD FileOrDirectory(std::string path)
{
	char *pathptr = &path[0u];
	struct stat s;
	if (stat(pathptr, &s) == 0)
	{
		if (s.st_mode & S_IFDIR)
		{
			return 1;
		}
		else if (s.st_mode & S_IFREG)
		{
			return 0;
		}
		else
		{
			return 2;
		}
	}
	else
	{
		return 2;
	}
}

// https://stackoverflow.com/questions/7011071/detect-32-bit-or-64-bit-of-windows
DWORD osarch()
{
	DWORD NativeArch = PROCESSOR_ARCHITECTURE_INTEL; //assume 32 bit, if following checks fail it is 32 bit
	SYSTEM_INFO SystemInfo = { 0 };
	HINSTANCE hKernel = LoadLibraryA("kernel32.dll");

	if (!hKernel) //check kernel32 was loaded
		return NativeArch;
	FARPROC pGetNativeSystemInfo = GetProcAddress(hKernel, "GetNativeSystemInfo");
	if (!pGetNativeSystemInfo) //check that getnativesysteminfo exists
		return NativeArch;
	GetNativeSystemInfo(&SystemInfo);
	switch (SystemInfo.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		NativeArch = PROCESSOR_ARCHITECTURE_AMD64;
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		NativeArch = PROCESSOR_ARCHITECTURE_IA64;
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		NativeArch = PROCESSOR_ARCHITECTURE_INTEL;
		break;
	default:
		NativeArch = PROCESSOR_ARCHITECTURE_UNKNOWN;
		break;
	}
	FreeLibrary(hKernel); //loadlibrary closed by freelibrary
	return NativeArch;
}

std::string ps_arch(HANDLE hProcess)
{
	std::string return_string = "";
	BOOL wow64process;
	IsWow64Process(hProcess, &wow64process);
	if (osarch() == PROCESSOR_ARCHITECTURE_INTEL)
	{
		//std::wcout << "Arch: x32     ";
		return_string += "Arch: x32     ";
	}
	else
	{
		if (wow64process)
		{
			//std::wcout << "Arch: x32     ";
			return_string += "Arch: x32     ";
		}
		else
		{
			//std::wcout << "Arch: x64     ";
			return_string += "Arch: x64     ";
		}
	}
	return return_string;
}

//https://stackoverflow.com/questions/7560114/random-number-c-in-some-range
DWORD RandomNum(int lower, int upper)
{
	std::random_device rd; // obtain a random number from hardware
	std::mt19937 eng(rd()); // seed the generator
	std::uniform_int_distribution<> distr(lower, upper); // define the range
	return distr(eng); // generate numbers
}

void SleepJitter(DWORD sleep, DWORD jitter)
{
	// Calculate upper and lower range
	DWORD lower_range = sleep - round(sleep * (jitter / 100.0));
	DWORD upper_range = sleep + round(sleep * (jitter / 100.0));
	
	// Sleep for random time inbetween range
	DWORD sleep_time = RandomNum(lower_range, upper_range) * 1000;
	Sleep(sleep_time);
}
#endif // HELPER_H