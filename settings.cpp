#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include "settings.h"

BOOL(WINAPI* DllConvertSidToStringSidW)(PSID, LPWSTR*);
BOOL(WINAPI* DllConvertStringSidToSidW)(LPCWSTR, PSID*);
BOOL(WINAPI* DllLookupAccountNameW)(LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
NTSTATUS(WINAPI* DllLsaAddAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
NTSTATUS(WINAPI* DllLsaRemoveAccountRights)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
NTSTATUS(WINAPI* DllLsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
NTSTATUS(WINAPI* DllLsaEnumerateAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG);
ULONG(WINAPI* DllLsaNtStatusToWinError)(NTSTATUS);
NET_API_STATUS(NET_API_FUNCTION* DllNetLocalGroupEnum)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR); 
NET_API_STATUS(NET_API_FUNCTION* DllNetUserEnum)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD);
NET_API_STATUS(NET_API_FUNCTION* DllNetApiBufferFree)(_Frees_ptr_opt_ LPVOID);
NET_API_STATUS(NET_API_FUNCTION* DllNetUserAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
NET_API_STATUS(NET_API_FUNCTION* DllNetUserDel)(LPCWSTR, LPCWSTR);
NET_API_STATUS(NET_API_FUNCTION* DllNetUserChangePassword)(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
NET_API_STATUS(NET_API_FUNCTION* DllNetLocalGroupAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
NET_API_STATUS(NET_API_FUNCTION* DllNetLocalGroupDel)(LPCWSTR, LPCWSTR);
NET_API_STATUS(NET_API_FUNCTION* DllNetLocalGroupAddMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
NET_API_STATUS(NET_API_FUNCTION* DllNetLocalGroupDelMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
NET_API_STATUS(NET_API_FUNCTION* DllNetUserGetLocalGroups)(LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD);


HMODULE netapi32;
HMODULE advapi32;

void PrintError()
{
	PrintError();
}

void LoadAllLibs()
{
	netapi32 = LoadLibrary(L"C:\\Windows\\System32\\netapi32.dll");
	advapi32 = LoadLibrary(L"C:\\Windows\\System32\\Advapi32.dll");
}

void FreeAllLibs()
{
	FreeLibrary(netapi32);
	FreeLibrary(advapi32);
}

void GetFuncs()
{
	(FARPROC&)DllConvertSidToStringSidW = GetProcAddress(advapi32, "ConvertSidToStringSidW");
	(FARPROC&)DllConvertStringSidToSidW = GetProcAddress(advapi32, "ConvertStringSidToSidW");
	(FARPROC&)DllLsaOpenPolicy = GetProcAddress(advapi32, "LsaOpenPolicy");
	(FARPROC&)DllLsaEnumerateAccountRights = GetProcAddress(advapi32, "LsaEnumerateAccountRights");
	(FARPROC&)DllLsaNtStatusToWinError = GetProcAddress(advapi32, "LsaNtStatusToWinError");
	(FARPROC&)DllLsaRemoveAccountRights = GetProcAddress(advapi32, "LsaRemoveAccountRights");
	(FARPROC&)DllLsaAddAccountRights = GetProcAddress(advapi32, "LsaAddAccountRights");
	(FARPROC&)DllLookupAccountNameW = GetProcAddress(advapi32, "LookupAccountNameW");
	(FARPROC&)DllNetApiBufferFree = GetProcAddress(netapi32, "NetApiBufferFree");
	(FARPROC&)DllNetUserAdd = GetProcAddress(netapi32, "NetUserAdd");
	(FARPROC&)DllNetUserDel = GetProcAddress(netapi32, "NetUserDel");
	(FARPROC&)DllNetUserGetLocalGroups = GetProcAddress(netapi32, "NetUserGetLocalGroups");
	(FARPROC&)DllNetLocalGroupDel = GetProcAddress(netapi32, "NetLocalGroupDel");
	(FARPROC&)DllNetLocalGroupAdd = GetProcAddress(netapi32, "NetLocalGroupAdd");
	(FARPROC&)DllNetLocalGroupAddMembers = GetProcAddress(netapi32, "NetLocalGroupAddMembers");
	(FARPROC&)DllNetLocalGroupEnum = GetProcAddress(netapi32, "NetLocalGroupEnum");
	(FARPROC&)DllNetUserEnum = GetProcAddress(netapi32, "NetUserEnum");
	(FARPROC&)DllNetUserChangePassword = GetProcAddress(netapi32, "NetUserChangePassword");
	(FARPROC&)DllNetLocalGroupDelMembers = GetProcAddress(netapi32, "NetLocalGroupDelMembers");
}

void Help()
{
	printf("1 - Список пользователей\n");
	printf("2 - Создать пользователя\n");
	printf("3 - Удалить пользователя\n");
	printf("4 - Изменить пароль пользователя\n");
	printf("5 - Добавить привилегию пользователю\n");
	printf("6 - Удалить привилегию пользователя\n");
	printf("7 - Список групп\n");
	printf("8 - Создать группу\n");
	printf("9 - Удалить группу\n");
	printf("10 - Добавить пользователя в группу\n");
	printf("11 - Удалить пользователя из группы\n");
	printf("12 - Добавить привилегию группе\n");
	printf("13 - Удалить привилегию группы\n");
	printf("0 - Выход\n\n");
	printf("Введите команду: ");
}

int CheckEnter(int input)
{
	if (input < 0 || input > 15)
		return -1;
	else return input;
}

// Получение строки с SID пользователя/группы
LPWSTR GetStringSID(SID_NAME_USE sid_name_use, LPCWSTR name)
{
	PSID sid;
	DWORD cbSid = 0, cName = 0;
	LPWSTR domain;

	// Получение размера структуры
	DllLookupAccountNameW(NULL, name, NULL, &cbSid, NULL, &cName, &sid_name_use);
	cName = 500;
	sid = (PSID)malloc(cbSid);
	domain = (LPWSTR)malloc(sizeof(TCHAR) * (cName));
	memset(domain, 0, sizeof(TCHAR) * (cName));
	memset(sid, 0, cbSid);

	// Получение SID в виде структуры
	DllLookupAccountNameW(NULL, name, sid, &cbSid, domain, &cName, &sid_name_use);

	LPWSTR strsid;
	// Перевод структуры PSID в строку
	DllConvertSidToStringSidW(sid, &strsid);

	return strsid;
}

void GetAllGroups(LPWSTR u_name)
{
	LPLOCALGROUP_USERS_INFO_0 bufptr = NULL; //возвращаемые данные
	DWORD level = 0, flags = LG_INCLUDE_INDIRECT, prefmaxlen = MAX_PREFERRED_LENGTH, entriesread = 0, totalentries = 0;
	NET_API_STATUS nStatus;

	// Получение списка групп, в которых состоит пользователь
	nStatus = DllNetUserGetLocalGroups(NULL, u_name, level, flags, (LPBYTE*)&bufptr, prefmaxlen, &entriesread, &totalentries);

	if (nStatus == NERR_Success)
	{
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
		if ((pTmpBuf = bufptr) != NULL)
		{
			// Проходим по списку
			for (DWORD i = 0; i < entriesread; i++) // dwEntriesRead - количество фактически перечисленных элементов
			{
				if (pTmpBuf == NULL)
				{
					fprintf(stderr, "Нарушение доступа\n");
					break;
				}
				// Выводим название группы
				wprintf(L"\t%s\n", pTmpBuf->lgrui0_name);

				pTmpBuf++;
			}
		}
	}
	if (bufptr != NULL)
		DllNetApiBufferFree(bufptr);
}

void UsersList()
{
	LPUSER_INFO_0 bufptr = NULL, pTmpBuf;
	DWORD level = 0, prefmaxlen = MAX_PREFERRED_LENGTH, entriesread = 0, totalentries = 0, resume_handle = 0;
	NET_API_STATUS nStatus;
	DWORD i = MAX_COMPUTERNAME_LENGTH + 1;
	wchar_t pszServerName[MAX_COMPUTERNAME_LENGTH + 1];

	// Получение имени компьютера
	GetComputerNameW(pszServerName, &i);

	do
	{
		// Получение списока пользователей 
		nStatus = DllNetUserEnum(pszServerName, level, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&bufptr, prefmaxlen, &entriesread, &totalentries, &resume_handle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = bufptr) != NULL)
			{
				// Проходим по списку
				for (i = 0; i < entriesread; i++)
				{
					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "Нарушение доступа\n");
						break;
					}

					PLSA_UNICODE_STRING ss = nullptr;
					ULONG count_rights = 0;

					// Получение строки с SID пользователя по его имени
					LPWSTR sidstr = GetStringSID(SidTypeUser, pTmpBuf->usri0_name);

					wprintf(L"%s\t%s\n", pTmpBuf->usri0_name, sidstr);

					PSID sid;
					// Перевод строки с SID в структуру PSID
					DllConvertStringSidToSidW(sidstr, &sid);

					LSA_OBJECT_ATTRIBUTES ObjectAttributes;
					NTSTATUS ntsResult;
					LSA_HANDLE lsah;
					ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
					// Получение дескриптора объекта Policy
					ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

					// Вывод информации
					wprintf(L"- Группы пользователя:\n");
					GetAllGroups(pTmpBuf->usri0_name);

					wprintf(L"- Привилегии пользователя:\n");
					NTSTATUS stat = DllLsaEnumerateAccountRights(lsah, sid, &ss, &count_rights);
					for (int i = 0; i < count_rights; i++)
					{
						wprintf(L"\t%s\n", ss[i].Buffer);
					}

					wprintf(L"\n");
					pTmpBuf++;
				}
			}
		}
		else
		{
			fprintf(stderr, "Системная ошибка: код %d\n", nStatus);
		}

		if (bufptr != NULL)
		{
			DllNetApiBufferFree(bufptr);
			bufptr = NULL;
		}
	} while (nStatus == ERROR_MORE_DATA); //Доступны другие записи
}

void GroupList()
{
	PGROUP_INFO_1 bufptr = NULL, pTmpBuf;
	DWORD level = 1, prefmaxlen = MAX_PREFERRED_LENGTH, entriesread = 0, totalentries = 0;
	PDWORD dwResumeHandle = 0;
	DWORD i;
	PDWORD_PTR resume_handle = 0;
	NET_API_STATUS nStatus;
	wchar_t pszServerName[MAX_COMPUTERNAME_LENGTH + 1];

	// Получение имени компьютера
	GetComputerNameW(pszServerName, &i);
	do
	{
		// Получение списка групп
		nStatus = DllNetLocalGroupEnum(pszServerName, level, (LPBYTE*)&bufptr, prefmaxlen, &entriesread, &totalentries, resume_handle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = bufptr) != NULL)
			{
				// Проходим по списку
				for (i = 0; i < entriesread; i++)
				{
					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "Нарушение доступа\n");
						break;
					}
					wprintf(L"%s\t%s\n", pTmpBuf->grpi1_name, GetStringSID(SidTypeGroup, pTmpBuf->grpi1_name));

					PLSA_UNICODE_STRING ss = nullptr;
					ULONG count_rights = 0;

					// Получение строки с SID группы по её имени
					LPWSTR sidstr = GetStringSID(SidTypeGroup, pTmpBuf->grpi1_name);
					PSID sid;
					// Перевод строки с SID в структуру PSID
					DllConvertStringSidToSidW(sidstr, &sid);

					LSA_OBJECT_ATTRIBUTES ObjectAttributes;
					NTSTATUS ntsResult;
					LSA_HANDLE lsah;
					ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

					// Получение дескриптора объекта Policy
					ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

					// Получение списка привилегий группы
					NTSTATUS stat = DllLsaEnumerateAccountRights(lsah, sid, &ss, &count_rights);
					wprintf(L"- Привилегии группы:\n");
					for (int i = 0; i < count_rights; i++)
					{
						wprintf(L"\t%s\n", ss[i].Buffer);
					}

					wprintf(L"\n");
					pTmpBuf++;
				}
			}
		}
	} while (nStatus == ERROR_MORE_DATA); //Доступны другие записи
}

void UserAdd()
{
	USER_INFO_1 ui;
	NET_API_STATUS nStatus;
	wchar_t u_name[256];
	wchar_t password[256];

	// Считывание данных
	printf("Введите имя пользователя: ");
	wscanf(L" %s", u_name);
	printf("Введите пароль: ");
	wscanf(L" %s", password);

	// Заполнение структуры с информацией о пользователе
	ui.usri1_name = u_name;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;

	// Добавление пользователя
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	nStatus = DllNetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"Пользователь добавлен\n\n", u_name);
	}
	else
	{
		fprintf(stderr, "Системная ошибка: код %d\n", nStatus);
		if (nStatus == NERR_UserExists)
		{
			printf("Пользователь с таким именем уже существует.\n\n");
		}
	}
}

void UserDelete()
{
	NET_API_STATUS nStatus;

	// Считывание данных
	wchar_t u_name[256];
	printf("Введите имя пользователя: ");
	wscanf(L" %s", u_name);

	// Удаление
	nStatus = DllNetUserDel(NULL, u_name);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"Пользователь удалён\n\n", u_name);
	}
	else
	{
		fprintf(stderr, "Системная ошибка: код %d\n", nStatus);
		if (nStatus == NERR_InvalidComputer)
		{
			printf("Недопустимое имя компьютера.\n");
		}
		if (nStatus == NERR_NotPrimary)
		{
			printf("Операция разрешена только на основном контроллере домена.\n");
		}
		if (nStatus == NERR_UserNotFound)
		{
			printf("Не удалось найти имя пользователя.\n");
		}
		if (nStatus == ERROR_ACCESS_DENIED)
		{
			printf("У пользователя нет доступа к запрошенной информации.\n");
		}
		printf("\n");
	}
}

void UserChangePassword()
{
	NET_API_STATUS nStatus;
	wchar_t u_name[256];
	wchar_t old_password[256];
	wchar_t new_password[256];

	// Считывание данных
	printf("Имя пользователя: ");
	wscanf(L" %s", u_name);
	printf("Старый пароль: ");
	wscanf(L" %s", old_password);
	printf("Новый пароль: ");
	wscanf(L" %s", new_password);

	// Изменение пароля
	nStatus = DllNetUserChangePassword(NULL, u_name, old_password, new_password);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"Пароль изменен\n\n");
	}
	else
	{
		fprintf(stderr, "Системная ошибка: код %d\n", nStatus);
		if (nStatus == ERROR_INVALID_PASSWORD)
		{
			printf("Неверный пароль.\n");
		}
		else if (nStatus == NERR_UserNotFound)
		{
			printf("Не удалось найти имя пользователя.\n");
		}
	}
}

// Функция для перевода строки с названием привилегии в структуру LSA_UNICODE_STRING
VOID InitUnicodeString(OUT PLSA_UNICODE_STRING pUnicodeString, IN PCWSTR pSourceString)
{
	ULONG Length = wcslen(pSourceString) * sizeof(WCHAR);
	pUnicodeString->Length = (USHORT)Length;
	pUnicodeString->MaximumLength = (USHORT)(Length + sizeof(WCHAR));
	pUnicodeString->Buffer = (PWSTR)pSourceString;
}

void UserAddPrivilege()
{
	// Считывание данных
	wchar_t u_name[256];
	printf("Введите имя пользователя: ");
	wscanf(L" %s", u_name);

	wchar_t privilege[256];
	printf("Введите привилегию: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// Перевод строки с названием привилегии в структуру LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// Получение строки с SIDом пользователя по его имени
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL && GetLastError() == 0)
	{
		// Строка с SIDом переводится в структуру PSID
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// Получение дескриптора объекта Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// Добавление привилегии
			NTSTATUS nStatus = DllLsaAddAccountRights(lsah, sid, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"Привилегия добавлена\n\n");
			}
			else
			{
				fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("Указанная привилегия не существует.\n\n");
				}
			}
		}
		else
		{
			printf("Ошибка: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("Ошибка: %d\n", GetLastError());
	}
}

void UserDelPrivilege()
{
	// Считывание данных
	wchar_t u_name[256];
	printf("Введите имя пользователя: ");
	wscanf(L" %s", u_name);

	wchar_t privilege[256];
	printf("Введите привилегию: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// Перевод строки с названием привилегии в структуру LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// Получение строки с SIDом пользователя по его имени
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL)
	{
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// Получение дескриптора объекта Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// Удаление привилегии
			NTSTATUS nStatus = DllLsaRemoveAccountRights(lsah, sid, FALSE, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"Привилегия удалена\n\n");
			}
			else
			{
				fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("Указанная привилегия не существует.\n\n");
				}
			}
		}
		else
		{
			printf("Ошибка: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("Ошибка: %d\n", GetLastError());
	}
}

void GroupAddPrivilege()
{
	// Считывание данных
	wchar_t g_name[256];
	printf("Введите название группы: ");
	wscanf(L" %s", g_name);

	wchar_t privilege[256];
	printf("Введите привилегию: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// Перевод строки с названием привилегии в структуру LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// Получение строки с SIDом группы по её названию
	sidstr = GetStringSID(SidTypeGroup, g_name);
	PSID sid;
	if (sidstr != NULL && GetLastError() == 0)
	{
		// Строку с SIDом переводим в структуру PSID
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// Получение дескриптора объекта Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// Добавление привилегии
			NTSTATUS nStatus = DllLsaAddAccountRights(lsah, sid, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"Привилегия добавлена\n\n");
			}
			else
			{
				fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("Указанная привилегия не существует.\n\n");
				}
			}
		}
		else
		{
			printf("Ошибка: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("Ошибка: %d\n", GetLastError());
	}
}

void GroupDelPrivilege()
{
	// Считывание данных
	wchar_t g_name[256];
	printf("Введите название группы: ");
	wscanf(L" %s", g_name);

	wchar_t privilege[256];
	printf("Введите привилегию: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// Перевод строки с названием привилегии в структуру LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// Получение строки с SIDом группы по её названию
	sidstr = GetStringSID(SidTypeGroup, g_name);
	PSID sid;
	if (sidstr != NULL)
	{
		// Строку с SIDом переводим в структуру PSID
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// Получение дескриптора объекта Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// Удаление привилегии
			NTSTATUS nStatus = DllLsaRemoveAccountRights(lsah, sid, FALSE, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"Привилегия удалена\n\n");
			}
			else
			{
				fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("Указанная привилегия не существует.\n\n");
				}
			}
		}
		else
		{
			printf("Ошибка: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("Ошибка: %d\n", GetLastError());
	}
}

void GroupAdd()
{
	NET_API_STATUS nStatus;

	// Считывание данных
	wchar_t g_name[256];
	printf("Введите название группы: ");
	wscanf(L" %s", g_name);

	// Заполнение структуры _LOCALGROUP_INFO_0 с названием группы
	_LOCALGROUP_INFO_0 a;
	a.lgrpi0_name = g_name;

	// Создаём группу
	nStatus = DllNetLocalGroupAdd(NULL, 0, (LPBYTE)&a, NULL);
	if (NERR_Success == nStatus)
	{
		printf("Группа добавлена\n\n", g_name);
	}
	else
	{
		fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
		if (ERROR_ALIAS_EXISTS == nStatus)
		{
			printf("Указанная локальная группа уже существует\n\n");
		}
		else if (NERR_GroupExists == nStatus)
		{
			printf("Группа с таким названием уже существует\n\n");
		}
		else if (NERR_NotPrimary == nStatus)
		{
			printf("Операция разрешена только на основном контроллере домена.\n\n");
		}
	}
}

void GroupDelete()
{
	NET_API_STATUS nStatus;

	// Считывание данных
	wchar_t g_name[256];
	printf("Введите название группы: ");
	wscanf(L" %s", g_name);

	// Удаление
	nStatus = DllNetLocalGroupDel(NULL, g_name);
	if (NERR_Success == nStatus)
	{
		printf("Группа удалена\n\n", g_name);
	}
	else
	{
		fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
		if (NERR_GroupNotFound == nStatus)
		{
			printf("Указанная группа не существует.\n\n");
		}
	}
}

void GroupAddUser()
{
	NET_API_STATUS nStatus;

	wchar_t g_name[256];
	wchar_t u_name[256];
	// Считывание данных
	printf("Введите название группы: ");
	wscanf(L" %s", g_name);
	printf("Введите имя пользователя: ");
	wscanf(L" %s", u_name);

	_LOCALGROUP_MEMBERS_INFO_0 a;
	LPWSTR sidstr = NULL;

	// Получение строки с SID пользователя по его имени
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL)
	{
		// Строку с SIDом переводим в структуру PSID
		bool c = DllConvertStringSidToSidW(sidstr, &sid);

		a.lgrmi0_sid = sid;
		if (c)
			if (DllConvertStringSidToSidW(sidstr, &sid))
			{
				// Добавление участника
				nStatus = DllNetLocalGroupAddMembers(NULL, g_name, 0, (LPBYTE)&a, 1);

				if (NERR_Success == nStatus)
				{
					printf("Пользователь добавлен\n\n");
				}
				else
				{
					fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
					if (ERROR_MEMBER_IN_ALIAS == nStatus)
					{
						printf("Пользователь уже был добавлен в указанную группу\n\n");
					}
					else if (ERROR_NO_SUCH_MEMBER == nStatus)
					{
						printf("Один или несколько указанных элементов не существуют.\n\n");
					}
					else if (NERR_GroupNotFound == nStatus)
					{
						printf("Указанная группа не существует\n\n");
					}
				}
			}
			else
			{
				PrintError();
			}
	}
	else
	{
		PrintError();
	}
}

void GroupDelUser()
{
	NET_API_STATUS nStatus;

	wchar_t g_name[256];
	wchar_t u_name[256];
	// Считывание данных
	printf("Введите название группы: ");
	wscanf(L" %s", g_name);
	printf("Введите имя пользователя: ");
	wscanf(L" %s", u_name);

	LOCALGROUP_MEMBERS_INFO_0 a;
	LPWSTR sidstr = NULL;
	// Получение строки с SID пользователя по его имени
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL)
	{
		// Перевод строки с SID в структуру PSID
		bool c = DllConvertStringSidToSidW(sidstr, &sid);

		a.lgrmi0_sid = sid;
		if (c)
		{
			// Удаление участника
			nStatus = DllNetLocalGroupDelMembers(NULL, g_name, 0, (LPBYTE)&a, 1);
			if (NERR_Success == nStatus)
			{
				printf("Пользователь удален из группы\n\n");
			}
			else
			{
				fprintf(stderr, "Системная ошибка: код %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (ERROR_MEMBER_NOT_IN_ALIAS == nStatus)
				{
					printf("Пользователь не являлся членом группы\n\n");
				}
				else if (ERROR_NO_SUCH_MEMBER == nStatus)
				{
					printf("Один или несколько указанных элементов не существуют.\n\n");
				}
				else if (NERR_GroupNotFound == nStatus)
				{
					printf("Указанная группа не существует\n\n");
				}
			}
		}
		else
		{
			PrintError();
		}
	}
	else
	{
		PrintError();
	}
}


BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))          // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

void EnableUserPrivilege()
{
	wchar_t username[256];
	printf("Введите имя пользователя: ");
	wscanf(L" %s", username);

	wchar_t privilege[256];
	printf("Введите привилегию: ");
	wscanf(L" %s", privilege);

	HANDLE hToken;
	if (!LogonUser(
		username,                   // Username
		L".",                       // Logon domain
		NULL,                       // Password (in this case, no password)
		LOGON32_LOGON_NETWORK,      // Logon type
		LOGON32_PROVIDER_DEFAULT,   // Logon provider
		&hToken))                   // Receiving handle to token
	{
		printf("LogonUser failed with error %d\n", GetLastError());
		return;
	}

	if (!SetPrivilege(hToken, privilege, TRUE))
	{
		printf("Failed to enable privilege.\n");
	}
	else
	{
		printf("Privilege '%ls' enabled for user '%ls'.\n", privilege, username);
	}

	CloseHandle(hToken);
}

void DisableUserPrivilege()
{
	wchar_t username[256];
	printf("Введите имя пользователя: ");
	wscanf(L" %s", username);

	wchar_t privilege[256];
	printf("Введите привилегию: ");
	wscanf(L" %s", privilege);

	HANDLE hToken;
	if (!LogonUser(
		username,                   // Username
		L".",                       // Logon domain
		NULL,                       // Password (in this case, no password)
		LOGON32_LOGON_NETWORK,      // Logon type
		LOGON32_PROVIDER_DEFAULT,   // Logon provider
		&hToken))                   // Receiving handle to token
	{
		printf("LogonUser failed with error %d\n", GetLastError());
		return;
	}

	if (!SetPrivilege(hToken, privilege, FALSE))
	{
		printf("Failed to disable privilege.\n");
	}
	else
	{
		printf("Privilege '%ls' disabled for user '%ls'.\n", privilege, username);
	}

	CloseHandle(hToken);
}
