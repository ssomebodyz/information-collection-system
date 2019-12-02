#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
using namespace std;
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#define msg_bytes 512
void recieve_client(SOCKET s, HCRYPTKEY hSessionKe);
char heap[msg_bytes];

int  main()
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct sockaddr_in addr;
	char sendbuf[] = "\n Checking";
	int iResult;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTKEY hPublicKey;
	HCRYPTKEY hPrivateKey;
	HCRYPTKEY hSessionKey;
	DWORD count = 0;
	char SessionKey[msg_bytes];

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	{
		if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
		{
			printf("\n CryptAcquireContext error: %u", GetLastError());
			return 0;
		}
	}
	CryptGenKey(hProv, CALG_RSA_KEYX, AT_KEYEXCHANGE, &hKey);
	CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPublicKey);
	CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPrivateKey);
    CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &count);
	BYTE* data = (BYTE*)malloc(count * sizeof(BYTE));
	CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, data, &count);
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("\n  WSAStartup failed with error: %d", iResult);
		return 1;
	}

	char ip[msg_bytes];
	char command[msg_bytes];
	char port[msg_bytes];
	cout << "\n List of commands : \nos_version \ncur_time \nsys_time \nmem_info \ndisk_info \ndisk_mem \naccess_rights (f/r) \nowner_info (f/r) \n ";
	cout << "\nEnter IP\n";
	while (true)
	{
		    scanf("%s", ip);
			cout << "\nEnter port: ";
			scanf("%s", port);
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			printf("ip : %s\n", ip);
			addr.sin_port = htons(atoi(port));
			addr.sin_addr.s_addr = inet_addr(ip);
			ConnectSocket = socket(AF_INET, SOCK_STREAM, 0);
			if (ConnectSocket == 0)
			{
				printf("\nSocket failed with error: %ld", WSAGetLastError());
				continue;
			}
			iResult = connect(ConnectSocket, (struct sockaddr*)&addr, sizeof(addr));
			if (iResult == SOCKET_ERROR)
			{
				printf("\nUnable to connect to server!");
				continue;
			}
			printf("\nConnected: %s", ip);
			iResult = send(ConnectSocket, (char*)data, count, 0);
			if (iResult == SOCKET_ERROR)
			{
				printf("\nPublic key sending error!");
				continue;
			}
			iResult = recv(ConnectSocket, SessionKey, msg_bytes, 0);
			if (iResult <= 0)
			{
				printf("\n Session key: error");
				continue;
			}
			printf("\nSession key: ok");
			CryptImportKey(hProv, (BYTE*)SessionKey, msg_bytes, hPrivateKey, 0, &hSessionKey);// s serva
			//// hProv Ц дескриптор CSP.
			// pbData Ц импортируемый ключ представленный в виде массива  байт.
			// dwDataLen Цдлина данных в pbData.
			//	hPubKey - дескриптор ключа, который расшифрует ключ содержащийс€ в pbData.
			//	dwFlags - флаги.
			//	phKey Ц указатель на дескриптор ключа.Ѕудет указывать на импортированный ключ.
			while (true)
			{
				scanf(" %[^\n]s", command);
				memcpy(heap, command, msg_bytes);
				DWORD buf_len = strlen(command);
				command[buf_len] = '\0';
				buf_len++;
				if (strcmp(command, "exit") == 0)
				{
					break;
				}
				CryptEncrypt(hSessionKey, 0, true, 0, (BYTE*)command, &buf_len, msg_bytes);
				//printf("encrypted command is %s \n", command);
				iResult = send(ConnectSocket, command, buf_len, 0);
				if (iResult == SOCKET_ERROR)
				{
					printf("\n Send error!");
					continue;
				}
				recieve_client(ConnectSocket, hSessionKey);
			}
			CryptDestroyKey(hSessionKey);
			printf("\n  Disconnect");
			closesocket(ConnectSocket);
	}
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyKey(hPublicKey);
	CryptDestroyKey(hPrivateKey);
	closesocket(ConnectSocket);
	WSACleanup();
	return 0;
}


void recieve_client(SOCKET s, HCRYPTKEY hSessionKey)
{
	char recvbuf[msg_bytes];
	int recvbuflen = msg_bytes;
	DWORD iResult;
	iResult = recv(s, recvbuf, recvbuflen, 0);
	if (iResult > 0)
	{
		CryptDecrypt(hSessionKey, 0, true, 0, (BYTE*)recvbuf, &iResult);
		if (strcmp(heap, "os_version") == 0)
		{
			//OSVERSIONINFOEX OSVer;
			char os_ver[msg_bytes / 12] = { 0 };
			memcpy(os_ver, recvbuf, sizeof(os_ver));
			cout << "\n"<<os_ver<<endl;
			/*if (OSVer.dwMajorVersion == 4)
			{
				if (OSVer.dwMinorVersion == 0)
				{
					cout << "\nWindows 95";
				}
				if (OSVer.dwMinorVersion == 10)
				{
					cout << "\nWindows 98";
				}
				if (OSVer.dwMinorVersion == 90)
				{
					cout << "\nWindowsMe";
				}
			}
			else if (OSVer.dwMajorVersion == 5)
			{
				if (OSVer.dwMinorVersion == 0)
				{
					cout << "\nWindows 2000";

				}
				if (OSVer.dwMinorVersion == 1)
				{
					cout << "\nWindows XP";
				}
				if (OSVer.dwMinorVersion == 2)
				{
					cout << "\nWindows 2003";
				}
			}
			else if (OSVer.dwMajorVersion == 6)
			{
				if (OSVer.dwMinorVersion == 0)
				{
					cout << "\nWindows Vista";
				}
				else if (OSVer.dwMinorVersion == 1)
				{
					cout << "\nWindows 7";
				}
				else if (OSVer.dwMinorVersion == 2)
				{
					cout << "\nWindows 10";
				}
				else if (OSVer.dwMinorVersion == 3)
				{
					cout << "\nWindows 8.1";
				}
			}
			else
			{
				cout << "\nUnknown version of Windows";
			}*/
		}
		else if (strcmp(heap, "cur_time") == 0)
		{
			SYSTEMTIME sm;
			memcpy(&sm, recvbuf, sizeof(SYSTEMTIME));
			printf("\nYear: %u, Month: %u, Day: %u, Hour: %u, Min: %u, Sec: %u", sm.wYear, sm.wMonth, sm.wDay, sm.wHour, sm.wMinute, sm.wSecond);
		}
		else if (strcmp(heap, "sys_time") == 0)
		{
			unsigned int hour, min, sec, msec;
			memcpy(&msec, recvbuf, sizeof(int));
			sec = msec / 1000;
			min = sec / 60;
			hour = min / 60;
			min %= 60;
			sec %= 60;
			printf("\nHour: %u, Min: %u, Sec: %u", hour, min, sec);
		}
		else if (strcmp(heap, "mem_info") == 0)
		{
			MEMORYSTATUS ms;
			memcpy(&ms, recvbuf, sizeof(MEMORYSTATUS));
			printf("\nMemory load: %u%%\nTotal phys: %u\nAvailable phys: %u\nTotal page file: %u\nAvailable page file: %u\nTotal virtual: %u\nAvailable virtual: %u",
				ms.dwMemoryLoad, ms.dwTotalPhys, ms.dwAvailPhys, ms.dwTotalPageFile, ms.dwAvailPageFile, ms.dwTotalVirtual, ms.dwAvailVirtual);
		}
		else if (strcmp(heap, "disk_info") == 0)
		{
			char Disks[26];
			unsigned int DiskType[26];
			memcpy(Disks, recvbuf, sizeof(Disks));
			memcpy(&DiskType, recvbuf + sizeof(Disks), sizeof(DiskType));
			for (int i = 0; i < 26; i++)
			{
				if (Disks[i])
				{
					printf("\n%c: ", Disks[i]);
					if (DiskType[i] == 0)
					{
						cout << "\nUnknown";
					}
					else if (DiskType[i] == 2)
					{
						cout << "\nRemovable";
					}
					else if (DiskType[i] == 3)
					{
						cout << "\nFixed";
					}
					else if (DiskType[i] == 4)
					{
						cout << "\nNetwork";
					}
					else if (DiskType[i] == 5)
					{
						cout << "\nCD-rom";
					}
					else if (DiskType[i] == 6)
					{
						cout << "\nRAM disk";
					}
				}
			}
		}
		else if (strcmp(heap, "disk_mem") == 0)
		{
			char Disks[26];
			double DiskMemory[26];
			memcpy(Disks, recvbuf, sizeof(Disks));
			memcpy(&DiskMemory, recvbuf + sizeof(Disks), sizeof(DiskMemory));
			for (int i = 0; i < 26; i++)
			{
				if (Disks[i])
				{
					printf("\n%c: %.2fGB", Disks[i], DiskMemory[i]);
				}
			}

		}
		else if (strncmp(heap, "access_rights", 13) == 0)
		{
			if (recvbuf[0] == '\0')
			{
				printf("\nWrong path");
				return;
			}
			printf("\n %s", recvbuf);
		}
		else if (strncmp(heap, "owner_info", 10) == 0)
		{
			if (recvbuf[0] == '\0')
			{
				printf("\nWrong path");
				return;
			}
			char SID[msg_bytes / 4];
			char Owner[msg_bytes / 4];
			char Domain[msg_bytes / 4];
			memcpy(SID, recvbuf, sizeof(SID));
			memcpy(Owner, recvbuf + sizeof(SID), sizeof(Owner));
			memcpy(Domain, recvbuf + sizeof(SID) + sizeof(Owner), sizeof(Domain));
			printf("\nSID : %s \nOwner : %s \nDomain : %s", SID, Owner, Domain);
		}
		else
		{
			printf("\nWrong command");
		}
	}
}
