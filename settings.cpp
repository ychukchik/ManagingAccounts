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
	printf("1 - ������ �������������\n");
	printf("2 - ������� ������������\n");
	printf("3 - ������� ������������\n");
	printf("4 - �������� ������ ������������\n");
	printf("5 - �������� ���������� ������������\n");
	printf("6 - ������� ���������� ������������\n");
	printf("7 - ������ �����\n");
	printf("8 - ������� ������\n");
	printf("9 - ������� ������\n");
	printf("10 - �������� ������������ � ������\n");
	printf("11 - ������� ������������ �� ������\n");
	printf("12 - �������� ���������� ������\n");
	printf("13 - ������� ���������� ������\n");
	printf("0 - �����\n\n");
	printf("������� �������: ");
}

int CheckEnter(int input)
{
	if (input < 0 || input > 15)
		return -1;
	else return input;
}

// ��������� ������ � SID ������������/������
LPWSTR GetStringSID(SID_NAME_USE sid_name_use, LPCWSTR name)
{
	PSID sid;
	DWORD cbSid = 0, cName = 0;
	LPWSTR domain;

	// ��������� ������� ���������
	DllLookupAccountNameW(NULL, name, NULL, &cbSid, NULL, &cName, &sid_name_use);
	cName = 500;
	sid = (PSID)malloc(cbSid);
	domain = (LPWSTR)malloc(sizeof(TCHAR) * (cName));
	memset(domain, 0, sizeof(TCHAR) * (cName));
	memset(sid, 0, cbSid);

	// ��������� SID � ���� ���������
	DllLookupAccountNameW(NULL, name, sid, &cbSid, domain, &cName, &sid_name_use);

	LPWSTR strsid;
	// ������� ��������� PSID � ������
	DllConvertSidToStringSidW(sid, &strsid);

	return strsid;
}

void GetAllGroups(LPWSTR u_name)
{
	LPLOCALGROUP_USERS_INFO_0 bufptr = NULL; //������������ ������
	DWORD level = 0, flags = LG_INCLUDE_INDIRECT, prefmaxlen = MAX_PREFERRED_LENGTH, entriesread = 0, totalentries = 0;
	NET_API_STATUS nStatus;

	// ��������� ������ �����, � ������� ������� ������������
	nStatus = DllNetUserGetLocalGroups(NULL, u_name, level, flags, (LPBYTE*)&bufptr, prefmaxlen, &entriesread, &totalentries);

	if (nStatus == NERR_Success)
	{
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
		if ((pTmpBuf = bufptr) != NULL)
		{
			// �������� �� ������
			for (DWORD i = 0; i < entriesread; i++) // dwEntriesRead - ���������� ���������� ������������� ���������
			{
				if (pTmpBuf == NULL)
				{
					fprintf(stderr, "��������� �������\n");
					break;
				}
				// ������� �������� ������
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

	// ��������� ����� ����������
	GetComputerNameW(pszServerName, &i);

	do
	{
		// ��������� ������� ������������� 
		nStatus = DllNetUserEnum(pszServerName, level, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&bufptr, prefmaxlen, &entriesread, &totalentries, &resume_handle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = bufptr) != NULL)
			{
				// �������� �� ������
				for (i = 0; i < entriesread; i++)
				{
					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "��������� �������\n");
						break;
					}

					PLSA_UNICODE_STRING ss = nullptr;
					ULONG count_rights = 0;

					// ��������� ������ � SID ������������ �� ��� �����
					LPWSTR sidstr = GetStringSID(SidTypeUser, pTmpBuf->usri0_name);

					wprintf(L"%s\t%s\n", pTmpBuf->usri0_name, sidstr);

					PSID sid;
					// ������� ������ � SID � ��������� PSID
					DllConvertStringSidToSidW(sidstr, &sid);

					LSA_OBJECT_ATTRIBUTES ObjectAttributes;
					NTSTATUS ntsResult;
					LSA_HANDLE lsah;
					ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
					// ��������� ����������� ������� Policy
					ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

					// ����� ����������
					wprintf(L"- ������ ������������:\n");
					GetAllGroups(pTmpBuf->usri0_name);

					wprintf(L"- ���������� ������������:\n");
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
			fprintf(stderr, "��������� ������: ��� %d\n", nStatus);
		}

		if (bufptr != NULL)
		{
			DllNetApiBufferFree(bufptr);
			bufptr = NULL;
		}
	} while (nStatus == ERROR_MORE_DATA); //�������� ������ ������
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

	// ��������� ����� ����������
	GetComputerNameW(pszServerName, &i);
	do
	{
		// ��������� ������ �����
		nStatus = DllNetLocalGroupEnum(pszServerName, level, (LPBYTE*)&bufptr, prefmaxlen, &entriesread, &totalentries, resume_handle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = bufptr) != NULL)
			{
				// �������� �� ������
				for (i = 0; i < entriesread; i++)
				{
					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "��������� �������\n");
						break;
					}
					wprintf(L"%s\t%s\n", pTmpBuf->grpi1_name, GetStringSID(SidTypeGroup, pTmpBuf->grpi1_name));

					PLSA_UNICODE_STRING ss = nullptr;
					ULONG count_rights = 0;

					// ��������� ������ � SID ������ �� � �����
					LPWSTR sidstr = GetStringSID(SidTypeGroup, pTmpBuf->grpi1_name);
					PSID sid;
					// ������� ������ � SID � ��������� PSID
					DllConvertStringSidToSidW(sidstr, &sid);

					LSA_OBJECT_ATTRIBUTES ObjectAttributes;
					NTSTATUS ntsResult;
					LSA_HANDLE lsah;
					ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

					// ��������� ����������� ������� Policy
					ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

					// ��������� ������ ���������� ������
					NTSTATUS stat = DllLsaEnumerateAccountRights(lsah, sid, &ss, &count_rights);
					wprintf(L"- ���������� ������:\n");
					for (int i = 0; i < count_rights; i++)
					{
						wprintf(L"\t%s\n", ss[i].Buffer);
					}

					wprintf(L"\n");
					pTmpBuf++;
				}
			}
		}
	} while (nStatus == ERROR_MORE_DATA); //�������� ������ ������
}

void UserAdd()
{
	USER_INFO_1 ui;
	NET_API_STATUS nStatus;
	wchar_t u_name[256];
	wchar_t password[256];

	// ���������� ������
	printf("������� ��� ������������: ");
	wscanf(L" %s", u_name);
	printf("������� ������: ");
	wscanf(L" %s", password);

	// ���������� ��������� � ����������� � ������������
	ui.usri1_name = u_name;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;

	// ���������� ������������
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	nStatus = DllNetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"������������ ��������\n\n", u_name);
	}
	else
	{
		fprintf(stderr, "��������� ������: ��� %d\n", nStatus);
		if (nStatus == NERR_UserExists)
		{
			printf("������������ � ����� ������ ��� ����������.\n\n");
		}
	}
}

void UserDelete()
{
	NET_API_STATUS nStatus;

	// ���������� ������
	wchar_t u_name[256];
	printf("������� ��� ������������: ");
	wscanf(L" %s", u_name);

	// ��������
	nStatus = DllNetUserDel(NULL, u_name);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"������������ �����\n\n", u_name);
	}
	else
	{
		fprintf(stderr, "��������� ������: ��� %d\n", nStatus);
		if (nStatus == NERR_InvalidComputer)
		{
			printf("������������ ��� ����������.\n");
		}
		if (nStatus == NERR_NotPrimary)
		{
			printf("�������� ��������� ������ �� �������� ����������� ������.\n");
		}
		if (nStatus == NERR_UserNotFound)
		{
			printf("�� ������� ����� ��� ������������.\n");
		}
		if (nStatus == ERROR_ACCESS_DENIED)
		{
			printf("� ������������ ��� ������� � ����������� ����������.\n");
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

	// ���������� ������
	printf("��� ������������: ");
	wscanf(L" %s", u_name);
	printf("������ ������: ");
	wscanf(L" %s", old_password);
	printf("����� ������: ");
	wscanf(L" %s", new_password);

	// ��������� ������
	nStatus = DllNetUserChangePassword(NULL, u_name, old_password, new_password);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"������ �������\n\n");
	}
	else
	{
		fprintf(stderr, "��������� ������: ��� %d\n", nStatus);
		if (nStatus == ERROR_INVALID_PASSWORD)
		{
			printf("�������� ������.\n");
		}
		else if (nStatus == NERR_UserNotFound)
		{
			printf("�� ������� ����� ��� ������������.\n");
		}
	}
}

// ������� ��� �������� ������ � ��������� ���������� � ��������� LSA_UNICODE_STRING
VOID InitUnicodeString(OUT PLSA_UNICODE_STRING pUnicodeString, IN PCWSTR pSourceString)
{
	ULONG Length = wcslen(pSourceString) * sizeof(WCHAR);
	pUnicodeString->Length = (USHORT)Length;
	pUnicodeString->MaximumLength = (USHORT)(Length + sizeof(WCHAR));
	pUnicodeString->Buffer = (PWSTR)pSourceString;
}

void UserAddPrivilege()
{
	// ���������� ������
	wchar_t u_name[256];
	printf("������� ��� ������������: ");
	wscanf(L" %s", u_name);

	wchar_t privilege[256];
	printf("������� ����������: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// ������� ������ � ��������� ���������� � ��������� LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// ��������� ������ � SID�� ������������ �� ��� �����
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL && GetLastError() == 0)
	{
		// ������ � SID�� ����������� � ��������� PSID
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// ��������� ����������� ������� Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// ���������� ����������
			NTSTATUS nStatus = DllLsaAddAccountRights(lsah, sid, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"���������� ���������\n\n");
			}
			else
			{
				fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("��������� ���������� �� ����������.\n\n");
				}
			}
		}
		else
		{
			printf("������: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("������: %d\n", GetLastError());
	}
}

void UserDelPrivilege()
{
	// ���������� ������
	wchar_t u_name[256];
	printf("������� ��� ������������: ");
	wscanf(L" %s", u_name);

	wchar_t privilege[256];
	printf("������� ����������: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// ������� ������ � ��������� ���������� � ��������� LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// ��������� ������ � SID�� ������������ �� ��� �����
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
			// ��������� ����������� ������� Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// �������� ����������
			NTSTATUS nStatus = DllLsaRemoveAccountRights(lsah, sid, FALSE, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"���������� �������\n\n");
			}
			else
			{
				fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("��������� ���������� �� ����������.\n\n");
				}
			}
		}
		else
		{
			printf("������: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("������: %d\n", GetLastError());
	}
}

void GroupAddPrivilege()
{
	// ���������� ������
	wchar_t g_name[256];
	printf("������� �������� ������: ");
	wscanf(L" %s", g_name);

	wchar_t privilege[256];
	printf("������� ����������: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// ������� ������ � ��������� ���������� � ��������� LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// ��������� ������ � SID�� ������ �� � ��������
	sidstr = GetStringSID(SidTypeGroup, g_name);
	PSID sid;
	if (sidstr != NULL && GetLastError() == 0)
	{
		// ������ � SID�� ��������� � ��������� PSID
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// ��������� ����������� ������� Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// ���������� ����������
			NTSTATUS nStatus = DllLsaAddAccountRights(lsah, sid, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"���������� ���������\n\n");
			}
			else
			{
				fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("��������� ���������� �� ����������.\n\n");
				}
			}
		}
		else
		{
			printf("������: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("������: %d\n", GetLastError());
	}
}

void GroupDelPrivilege()
{
	// ���������� ������
	wchar_t g_name[256];
	printf("������� �������� ������: ");
	wscanf(L" %s", g_name);

	wchar_t privilege[256];
	printf("������� ����������: ");
	wscanf(L" %s", privilege);

	LSA_UNICODE_STRING tmp;
	// ������� ������ � ��������� ���������� � ��������� LSA_UNICODE_STRING
	InitUnicodeString(&tmp, privilege);
	LPWSTR sidstr = NULL;
	// ��������� ������ � SID�� ������ �� � ��������
	sidstr = GetStringSID(SidTypeGroup, g_name);
	PSID sid;
	if (sidstr != NULL)
	{
		// ������ � SID�� ��������� � ��������� PSID
		if (DllConvertStringSidToSidW(sidstr, &sid))
		{
			LSA_OBJECT_ATTRIBUTES ObjectAttributes;
			NTSTATUS ntsResult;
			LSA_HANDLE lsah;
			ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
			// ��������� ����������� ������� Policy
			ntsResult = DllLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &lsah);

			// �������� ����������
			NTSTATUS nStatus = DllLsaRemoveAccountRights(lsah, sid, FALSE, &tmp, 1);
			if (nStatus == 0)
			{
				fwprintf(stderr, L"���������� �������\n\n");
			}
			else
			{
				fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (nStatus == ERROR_NO_SUCH_PRIVILEGE)
				{
					printf("��������� ���������� �� ����������.\n\n");
				}
			}
		}
		else
		{
			printf("������: %d\n", GetLastError());
			return;
		}
	}
	else
	{
		printf("������: %d\n", GetLastError());
	}
}

void GroupAdd()
{
	NET_API_STATUS nStatus;

	// ���������� ������
	wchar_t g_name[256];
	printf("������� �������� ������: ");
	wscanf(L" %s", g_name);

	// ���������� ��������� _LOCALGROUP_INFO_0 � ��������� ������
	_LOCALGROUP_INFO_0 a;
	a.lgrpi0_name = g_name;

	// ������ ������
	nStatus = DllNetLocalGroupAdd(NULL, 0, (LPBYTE)&a, NULL);
	if (NERR_Success == nStatus)
	{
		printf("������ ���������\n\n", g_name);
	}
	else
	{
		fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
		if (ERROR_ALIAS_EXISTS == nStatus)
		{
			printf("��������� ��������� ������ ��� ����������\n\n");
		}
		else if (NERR_GroupExists == nStatus)
		{
			printf("������ � ����� ��������� ��� ����������\n\n");
		}
		else if (NERR_NotPrimary == nStatus)
		{
			printf("�������� ��������� ������ �� �������� ����������� ������.\n\n");
		}
	}
}

void GroupDelete()
{
	NET_API_STATUS nStatus;

	// ���������� ������
	wchar_t g_name[256];
	printf("������� �������� ������: ");
	wscanf(L" %s", g_name);

	// ��������
	nStatus = DllNetLocalGroupDel(NULL, g_name);
	if (NERR_Success == nStatus)
	{
		printf("������ �������\n\n", g_name);
	}
	else
	{
		fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
		if (NERR_GroupNotFound == nStatus)
		{
			printf("��������� ������ �� ����������.\n\n");
		}
	}
}

void GroupAddUser()
{
	NET_API_STATUS nStatus;

	wchar_t g_name[256];
	wchar_t u_name[256];
	// ���������� ������
	printf("������� �������� ������: ");
	wscanf(L" %s", g_name);
	printf("������� ��� ������������: ");
	wscanf(L" %s", u_name);

	_LOCALGROUP_MEMBERS_INFO_0 a;
	LPWSTR sidstr = NULL;

	// ��������� ������ � SID ������������ �� ��� �����
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL)
	{
		// ������ � SID�� ��������� � ��������� PSID
		bool c = DllConvertStringSidToSidW(sidstr, &sid);

		a.lgrmi0_sid = sid;
		if (c)
			if (DllConvertStringSidToSidW(sidstr, &sid))
			{
				// ���������� ���������
				nStatus = DllNetLocalGroupAddMembers(NULL, g_name, 0, (LPBYTE)&a, 1);

				if (NERR_Success == nStatus)
				{
					printf("������������ ��������\n\n");
				}
				else
				{
					fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
					if (ERROR_MEMBER_IN_ALIAS == nStatus)
					{
						printf("������������ ��� ��� �������� � ��������� ������\n\n");
					}
					else if (ERROR_NO_SUCH_MEMBER == nStatus)
					{
						printf("���� ��� ��������� ��������� ��������� �� ����������.\n\n");
					}
					else if (NERR_GroupNotFound == nStatus)
					{
						printf("��������� ������ �� ����������\n\n");
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
	// ���������� ������
	printf("������� �������� ������: ");
	wscanf(L" %s", g_name);
	printf("������� ��� ������������: ");
	wscanf(L" %s", u_name);

	LOCALGROUP_MEMBERS_INFO_0 a;
	LPWSTR sidstr = NULL;
	// ��������� ������ � SID ������������ �� ��� �����
	sidstr = GetStringSID(SidTypeUser, u_name);
	PSID sid;
	if (sidstr != NULL)
	{
		// ������� ������ � SID � ��������� PSID
		bool c = DllConvertStringSidToSidW(sidstr, &sid);

		a.lgrmi0_sid = sid;
		if (c)
		{
			// �������� ���������
			nStatus = DllNetLocalGroupDelMembers(NULL, g_name, 0, (LPBYTE)&a, 1);
			if (NERR_Success == nStatus)
			{
				printf("������������ ������ �� ������\n\n");
			}
			else
			{
				fprintf(stderr, "��������� ������: ��� %lu\n", (DllLsaNtStatusToWinError)(nStatus));
				if (ERROR_MEMBER_NOT_IN_ALIAS == nStatus)
				{
					printf("������������ �� ������� ������ ������\n\n");
				}
				else if (ERROR_NO_SUCH_MEMBER == nStatus)
				{
					printf("���� ��� ��������� ��������� ��������� �� ����������.\n\n");
				}
				else if (NERR_GroupNotFound == nStatus)
				{
					printf("��������� ������ �� ����������\n\n");
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
	printf("������� ��� ������������: ");
	wscanf(L" %s", username);

	wchar_t privilege[256];
	printf("������� ����������: ");
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
	printf("������� ��� ������������: ");
	wscanf(L" %s", username);

	wchar_t privilege[256];
	printf("������� ����������: ");
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
