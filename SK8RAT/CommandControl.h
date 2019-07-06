#ifndef COMMANDCONTROL_H
#define COMMANDCONTROL_H
#include <windows.h>
#include <winhttp.h>
#include <string>
#include "Agent.h"

std::string agent_get(std::string domain, int port, std::string url, std::string &response)
{
	std::wstring wstrDomain = GetUTF16(domain, CP_UTF8);
	std::wstring wstrUrl = GetUTF16(url, CP_UTF8);
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
		hConnect = WinHttpConnect(hSession, wstrDomain.c_str() ,
			port, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", wstrUrl.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	//printf("Sending GET to server ...\n");

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
				//printf("Server Response: %s\n", pszOutBuffer);
				std::string stdstr = pszOutBuffer;
				response = stdstr;
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

void agent_post(std::string domain, int port, std::string url, std::string send, std::string &response)
{
	std::wstring wstrDomain = GetUTF16(domain, CP_UTF8);
	std::wstring wstrUrl = GetUTF16(url, CP_UTF8);
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
		hConnect = WinHttpConnect(hSession, wstrDomain.c_str(),
			port, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"POST", wstrUrl.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

	// Send a request.
	LPSTR  data = const_cast<char *>(send.c_str());;
	DWORD data_len = strlen(data);
	DWORD headersLength = -1;
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, headersLength,
			data, data_len,
			data_len, 0);
	//printf("Sending POST to server ...\n");

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
				//printf("Server response: %s\n", pszOutBuffer);
				std::string stdstr = pszOutBuffer;
				response = stdstr;
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

std::string agent_get_cookie(std::string domain, int port, std::string url, std::string cookie, std::string &response)
{
	std::wstring wstrDomain = GetUTF16(domain, CP_UTF8);
	std::wstring wstrUrl = GetUTF16(url, CP_UTF8);
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
		hConnect = WinHttpConnect(hSession, wstrDomain.c_str(),
			port, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", wstrUrl.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

	// Send a request.
	std::string headers = "Cookie: macaroon=" + cookie;
	std::wstring wheaders = GetUTF16(headers, CP_UTF8);
	LPCWSTR lpcwheaders = wheaders.c_str();
	DWORD headersLength = wcslen(lpcwheaders);
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			lpcwheaders, headersLength,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	//printf("Sending GET to server ...\n");

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
				//printf("Server Response: %s\n", pszOutBuffer);
				std::string stdstr = pszOutBuffer;
				response = stdstr;
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

void agent_post_cookie(std::string domain, int port, std::string url, std::string cookie, std::string send, std::string &response)
{
	std::wstring wstrDomain = GetUTF16(domain, CP_UTF8);
	std::wstring wstrUrl = GetUTF16(url, CP_UTF8);
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
		hConnect = WinHttpConnect(hSession, wstrDomain.c_str(),
			port, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"POST", wstrUrl.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

	// Send a request.
	LPSTR  data = const_cast<char *>(send.c_str());;
	DWORD data_len = strlen(data);
	std::string headers = "Cookie: macaroon=" + cookie;
	std::wstring wheaders = GetUTF16(headers, CP_UTF8);
	LPCWSTR lpcwheaders = wheaders.c_str();
	DWORD headersLength = wcslen(lpcwheaders);
	//printf("%s\n%S\n%S\nheader length: %i\n", headers.c_str(), wheaders.c_str(), lpcwheaders, headersLength);
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			lpcwheaders, headersLength,
			data, data_len,
			data_len, 0);
	//printf("Sending POST to server ...\n");

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
				//printf("Server response: %s\n", pszOutBuffer);
				std::string stdstr = pszOutBuffer;
				response = stdstr;
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
#endif //COMMANDCONTROL_H