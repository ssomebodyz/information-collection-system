#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winsock2.h>
#include <wincrypt.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"mswsock.lib")
#pragma warning(disable:4996)
#define MAX_CLIENTS (100)
#define msg_bytes 512

class spy
{
public:
	OSVERSIONINFOEX os_version;
    SYSTEMTIME current_time;
    unsigned int os_time;
	MEMORYSTATUS memory_info;
	char disks[26];
	char os_ver[msg_bytes/12] = { 0 };
	unsigned int type_of_disk[26];
	double free_memory_of_disk[26];
	char SIID[msg_bytes / 4];
	char master[msg_bytes / 4];
    char host[msg_bytes / 4];
	char access_rights[msg_bytes];

	void get_spy_info() 
	{       
		    DWORD BufferSize = sizeof(os_ver);
		    char os_ver[msg_bytes/12] = { 0 };
		    RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", RRF_RT_ANY, NULL, &os_ver, &BufferSize);
			ZeroMemory(&(os_version), sizeof(os_version));
			os_version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
			GetVersionEx((LPOSVERSIONINFOA)(&(os_version)));
			GetLocalTime(&(current_time));
			os_time = GetTickCount();
			GlobalMemoryStatus(&(memory_info));
			char Disks[26][3] = { 0 };//узнаем какие в целом на компьютере существуют диски
			DWORD dr = GetLogicalDrives();
			for (int i = 0, count = 0, n; i < 26; i++)
			{
				n = ((dr >> i) & 0x00000001);
				if (n == 1)
				{
					Disks[count][0] = char(65 + i);
					Disks[count][1] = ':';
					disks[count] = char(65 + i);
					type_of_disk[count] = GetDriveTypeA(Disks[count]);
					if (type_of_disk[count] == DRIVE_FIXED)
					{
						DWORD s, b, f, c;
						GetDiskFreeSpaceA(Disks[count], &s, &b, &f, &c);//sectors per cluster, bytes per sector, total free clusters, available clusters for current user
						free_memory_of_disk[count] = (double)f*(double)s*(double)b / 1024.0 / 1024.0 / 1024.0;
					}

					count++;
				}
			}

	}
	void get_access_rights(char *path, int type) 
	{
		PACL pDACL = NULL; //структура pacl
		PSECURITY_DESCRIPTOR pSD = NULL; //структура дескриптора
		DWORD dwRes;
		char Sid[128];
		if (type == 1)
		{
			dwRes = GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS;
		}
		else
		{
			HKEY result;
			RegOpenKey(HKEY_CURRENT_USER, path, &result);
			if (!strncmp(path, "HKEY_CLASSES_ROOT", strlen("HKEY_CLASSES_ROOT")))
			{
				RegOpenKey(HKEY_CLASSES_ROOT, path + strlen("HKEY_CLASSES_ROOT") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_CURRENT_CONFIG", strlen("HKEY_CURRENT_CONFIG")))
			{
				RegOpenKey(HKEY_CURRENT_CONFIG, path + strlen("HKEY_CURRENT_CONFIG") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_CURRENT_USER", strlen("HKEY_CURRENT_USER")))
			{
				RegOpenKey(HKEY_CURRENT_USER, path + strlen("HKEY_CURRENT_USER") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_LOCAL_MACHINE", strlen("HKEY_LOCAL_MACHINE")))
			{
				RegOpenKey(HKEY_LOCAL_MACHINE, path + strlen("HKEY_LOCAL_MACHINE") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_USERS", strlen("HKEY_USERS")))
			{
				RegOpenKey(HKEY_USERS, path + strlen("HKEY_USERS") + 1, &result);
			}
			GetSecurityInfo(result, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD);
			//dwRes = GetNamedSecurityInfo(path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS;
		}
		if (pDACL == NULL) { printf("\nno found rights\n"); }
		//if (dwRes != ERROR_SUCCESS)
		//{
		//	LocalFree(pSD);//освобождение занятой локальной памяти
		//	return;
		//}
		if (pDACL != NULL)
		{
			ACL_SIZE_INFORMATION aclInfo;
			GetAclInformation(pDACL, &aclInfo, sizeof(aclInfo), AclSizeInformation);
			SID_NAME_USE sid_n;
			LPSTR temp_SID = NULL;
			DWORD length = 200;
			BOOL flag1;
			char current_spy[msg_bytes / 4];
			char current_host[msg_bytes / 4];
			for (DWORD i = 0; i < aclInfo.AceCount; i++)
			{
				ACCESS_ALLOWED_ACE *ace;
				if (GetAce(pDACL, i, (LPVOID*)&ace))
				{
					SID *SidStart = (SID*)&(ace->SidStart);
					if (LookupAccountSid(NULL, SidStart, current_spy, &length, current_host, &length, &sid_n))
					{
						strcpy(access_rights, "Account: ");
						strcat(access_rights, current_spy);
					}
					flag1 = ConvertSidToStringSid(SidStart, &temp_SID);
					strcpy(Sid, temp_SID);
					strcat(access_rights, "\nAccount SID: ");
					strcat(access_rights, Sid);
					if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
					{
						strcat(access_rights, "\nAllowed  ");
					}
					else
					{
						strcat(access_rights, "\nDenied  ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & 1)
					{
						strcat(access_rights, "GENERIC_READ ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & 2)
					{
						strcat(access_rights, "GENERIC_WRITE ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & 4)
					{
						strcat(access_rights, "GENERIC_EXECUTE ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & SYNCHRONIZE)
					{
						strcat(access_rights, "SYNCHRONIZE ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & WRITE_OWNER)
					{
						strcat(access_rights, "WRITE_OWNER ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & WRITE_DAC)
					{
						strcat(access_rights, "WRITE_DAC ");
					}
					if (((ACCESS_ALLOWED_ACE *)ace)->Mask & DELETE)
					{
						strcat(access_rights, "DELETE ");
					}
				}
			}
		}
	}
	void get_master_access(char *path, int type) 
	{
		DWORD dwRes;
		PSID pOwnerSID;
		PSECURITY_DESCRIPTOR pSecDescr;
		if (type == 1)
		{
			dwRes = GetNamedSecurityInfo(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
		}
		else
		{
			HKEY result;
			RegOpenKey(HKEY_CURRENT_USER, path , &result);
			if (!strncmp(path, "HKEY_CLASSES_ROOT", strlen("HKEY_CLASSES_ROOT"))) 
			{
				RegOpenKey(HKEY_CLASSES_ROOT, path + strlen("HKEY_CLASSES_ROOT") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_CURRENT_CONFIG", strlen("HKEY_CURRENT_CONFIG")))
			{
				RegOpenKey(HKEY_CURRENT_CONFIG, path + strlen("HKEY_CURRENT_CONFIG") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_CURRENT_USER", strlen("HKEY_CURRENT_USER"))) 
			{
				RegOpenKey(HKEY_CURRENT_USER, path + strlen("HKEY_CURRENT_USER") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_LOCAL_MACHINE", strlen("HKEY_LOCAL_MACHINE")))
{
				RegOpenKey(HKEY_LOCAL_MACHINE, path + strlen("HKEY_LOCAL_MACHINE") + 1, &result);
			}
			else if (!strncmp(path, "HKEY_USERS", strlen("HKEY_USERS")))
			{
				RegOpenKey(HKEY_USERS, path + strlen("HKEY_USERS") + 1, &result);
			}
			GetSecurityInfo(result, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
			//dwRes = GetNamedSecurityInfo(path, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
		}
		/*if (dwRes != ERROR_SUCCESS)
		{
			LocalFree(pSecDescr);
			return;
		}*/
		DWORD dwUserNameLength = sizeof(master);
		DWORD dwDomainNameLength = sizeof(host);
		SID_NAME_USE sidUse;
		dwRes = LookupAccountSid(NULL, pOwnerSID, (LPSTR)&master, &dwUserNameLength, (LPSTR)&host, &dwDomainNameLength, &sidUse);
		if (dwRes == 0)
		{
			int iErr = GetLastError();
			return;
		}
		else
		{
			LPSTR SID;
			BOOL flag = ConvertSidToStringSid(pOwnerSID, &SID);
			strcpy(SIID, SID);
		}
	}

};
struct client_ctx
{
	int socket;
	CHAR buf_recv[msg_bytes];           // Буфер приема
	CHAR buf_send[msg_bytes];           // Буфер отправки
	unsigned int sz_recv;         // Принято данных
	unsigned int sz_send_total;   // Данных в буфере отправки
	unsigned int sz_send;         // Данных отправлено
								  // Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv
	HCRYPTKEY hSessionKey;
	int bSessionKey;
};
// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;
//Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i;
	// Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, (struct sockaddr**) &local_addr, &local_addr_sz, (struct sockaddr**) &remote_addr, &remote_addr_sz);

			if (remote_addr)
				ip = ntohl(remote_addr->sin_addr.s_addr);

			printf("\n connection %u created, remote IP: %u.%u.%u.%u", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff); g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("\n CreateIoCompletionPort error: %x", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление.
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\0')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	return  0;
}

spy steal_info;

void show_spy_info(int key)
{
	steal_info.get_spy_info();

	if (strcmp(g_ctxs[key].buf_recv, "os_version") == 0)
	{
		g_ctxs[key].sz_send_total = sizeof(OSVERSIONINFOEX);
		memcpy(g_ctxs[key].buf_send, steal_info.os_ver, g_ctxs[key].sz_send_total);
	}

	else if (strcmp(g_ctxs[key].buf_recv, "cur_time") == 0)
	{
		g_ctxs[key].sz_send_total = sizeof(SYSTEMTIME);
		memcpy(g_ctxs[key].buf_send, &(steal_info.current_time), g_ctxs[key].sz_send_total);
	}

	else if (strcmp(g_ctxs[key].buf_recv, "sys_time") == 0)
	{
		g_ctxs[key].sz_send_total = sizeof(int);
		memcpy(g_ctxs[key].buf_send, &(steal_info.os_time), g_ctxs[key].sz_send_total);
	}

	else if (strcmp(g_ctxs[key].buf_recv, "mem_info") == 0)
	{
		g_ctxs[key].sz_send_total = sizeof(MEMORYSTATUS);
		memcpy(g_ctxs[key].buf_send, &(steal_info.memory_info), g_ctxs[key].sz_send_total);
	}

	else if (strcmp(g_ctxs[key].buf_recv, "disk_info") == 0)
	{
		g_ctxs[key].sz_send_total = sizeof(steal_info.disks) + sizeof(steal_info.type_of_disk);
		memcpy(g_ctxs[key].buf_send, steal_info.disks, sizeof(steal_info.disks));
		memcpy(g_ctxs[key].buf_send + sizeof(steal_info.disks), steal_info.type_of_disk, sizeof(steal_info.type_of_disk));
	}

	else if (strcmp(g_ctxs[key].buf_recv, "disk_mem") == 0)
	{
		g_ctxs[key].sz_send_total = sizeof(steal_info.disks) + sizeof(steal_info.free_memory_of_disk);
		memcpy(g_ctxs[key].buf_send, steal_info.disks, sizeof(steal_info.disks));
		memcpy(g_ctxs[key].buf_send + sizeof(steal_info.disks), steal_info.free_memory_of_disk, sizeof(steal_info.free_memory_of_disk));
	}

	else if (strncmp(g_ctxs[key].buf_recv, "access_rights", 12) == 0)

	{
		if (g_ctxs[key].buf_recv[14] == 'f')
			steal_info.get_access_rights(g_ctxs[key].buf_recv + 16, 1);
		else if (g_ctxs[key].buf_recv[14] == 'r')
			steal_info.get_access_rights(g_ctxs[key].buf_recv + 16, 0);
		g_ctxs[key].sz_send_total = sizeof(steal_info.access_rights);
		memcpy(g_ctxs[key].buf_send, steal_info.access_rights, sizeof(steal_info.access_rights));
	}

	else if (strncmp(g_ctxs[key].buf_recv, "owner_info", 10) == 0)
	{
		if (g_ctxs[key].buf_recv[11] == 'f')
			steal_info.get_master_access(g_ctxs[key].buf_recv + 13, 1);
		else if (g_ctxs[key].buf_recv[11] == 'r')
			steal_info.get_master_access(g_ctxs[key].buf_recv + 13, 0);
		g_ctxs[key].sz_send_total = sizeof(steal_info.SIID) + sizeof(steal_info.master) + sizeof(steal_info.host);
		memcpy(g_ctxs[key].buf_send, steal_info.SIID, sizeof(steal_info.SIID));
		memcpy(g_ctxs[key].buf_send + sizeof(steal_info.SIID), steal_info.master, sizeof(steal_info.master));
		memcpy(g_ctxs[key].buf_send + sizeof(steal_info.SIID) + sizeof(steal_info.host), steal_info.host, sizeof(steal_info.host));
	}
	else
	{
		char warning[] = "Wrong command. Please try again.";
		g_ctxs[key].sz_send_total = sizeof(warning);
		memcpy(g_ctxs[key].buf_send, warning, sizeof(warning));
	}
	CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE*)g_ctxs[key].buf_send, (DWORD*)&g_ctxs[key].sz_send_total, msg_bytes);
	g_ctxs[key].sz_send = 0;
	memset(&steal_info, 0, sizeof(steal_info));
}

void io_serv(int port)
{
	WSADATA wsa_data;
	HCRYPTPROV hProv;// дескриптор CSP
	HCRYPTKEY hPublicKey;// дескриптор публичного ключа, расшифровывающий ключ pbData 
	DWORD count = 0;
	BYTE* data;
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	{
		if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
		{
			printf("\n CryptAcquireContext error: %u", GetLastError());
			return;
		}
	}
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("\n  WSAStartup ready");
	}
	else
	{
		printf("\n  WSAStartup error");
	}
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("\n CreateIoCompletionPort error: %x", GetLastError());
		return;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("\n  Error bind() or listen()");
		return;
	}
	printf("\n Listening: %hu", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("\n CreateIoCompletionPort error: %x", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;

	// Старт операции принятия подключения.
	schedule_accept();

	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		int temp_sock;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;

					if (!g_ctxs[key].bSessionKey)//конец сеанса
					{
						g_ctxs[key].bSessionKey = 1;
						CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &g_ctxs[key].hSessionKey);//seans
						CryptImportKey(hProv, (BYTE*)g_ctxs[key].buf_recv, g_ctxs[key].sz_recv, 0, 0, &hPublicKey);
						CryptExportKey(g_ctxs[key].hSessionKey, hPublicKey, SIMPLEBLOB, 0, NULL, &count);
						data = (BYTE*)malloc(count * sizeof(BYTE));
						CryptExportKey(g_ctxs[key].hSessionKey, hPublicKey, SIMPLEBLOB, 0, data, &count);
						g_ctxs[key].sz_send_total = count;
						memcpy(g_ctxs[key].buf_send, data, g_ctxs[key].sz_send_total);
						g_ctxs[key].sz_send = 0;
						free(data);
						CryptDestroyKey(hPublicKey);
						schedule_write(key);
					}
					else
					{
						CryptDecrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE*)g_ctxs[key].buf_recv, (DWORD*)&g_ctxs[key].sz_recv);
						printf("\n Command: %s", g_ctxs[key].buf_recv);
						int len;

						if (!is_string_received(key, &len))
						{
							CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE*)g_ctxs[key].buf_recv, (DWORD*)&g_ctxs[key].sz_recv, msg_bytes);
							schedule_read(key);
							continue;
						}

						if (strcmp(g_ctxs[key].buf_recv, "exit") == 0)
						{
							CancelIo((HANDLE)g_ctxs[key].socket);
							PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
							continue;
						}
						show_spy_info(key);
						schedule_write(key);
					}

				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						//CancelIo((HANDLE)g_ctxs[key].socket);
						//PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						temp_sock = g_ctxs[key].socket;
						HCRYPTKEY temp_key = g_ctxs[key].hSessionKey;//временный ключ~сеансовый ключ
						memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
						g_ctxs[key].socket = temp_sock;
						g_ctxs[key].hSessionKey = temp_key;
						g_ctxs[key].bSessionKey = 1;
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					CryptDestroyKey(g_ctxs[key].hSessionKey);//освобождение ранее полученного хэндла ключа
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf("\n  Connection %u Closed", key);
				}
			}
		}
		else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
		}
	}
}

int main()
{
	char tempbuff[msg_bytes];
	cout << "\nEnter port : ";
	scanf("%s", tempbuff);
	io_serv(atoi(tempbuff));
	return 0;
}