//������:
//����������� ��������� ��� ���������� �������� �������� � ���������
//������� � �� Windows, ������������ ����������� Windows API.

//���������� :
//- ���� ���������������� : C / C++;
//- ������������ ��������� ��������� Windows, ����������� ������� Windows API;
//- ��������������� ��������� �� ������ ������������ ������� ������� ��� Windows API;
//- ��������� ������ �������� ������ ������������������ � ������� ������������� � �����, �� SID � ����������;
//- ��������� ������ ��������� ��������� / �������� / ������� ������������� � ������ � ��, � ����� ������� � ���������, �������� � ��������� �� ����������;
//- ��������� ������ � �� Windows 7 � 10.

#pragma once
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <ntsecapi.h>
#include <lm.h>
#include <sddl.h>
#include <locale.h>

void PrintError();
LPWSTR GetStringSID(SID_NAME_USE sid_name_use, LPCWSTR name);
VOID InitUnicodeString(OUT PLSA_UNICODE_STRING pUnicodeString, IN PCWSTR pSourceString);
void GetAllGroups(LPWSTR username);
void LoadAllLibs();
void FreeAllLibs();
void Help();
void GetFuncs();
int CheckEnter(int input);

void UsersList();
void UserAdd();
void UserDelete();
void UserChangePassword();
void UserAddPrivilege();
void UserDelPrivilege();

void GroupList();
void GroupAdd();
void GroupDelete();
void GroupAddPrivilege();
void GroupDelPrivilege();
void GroupAddUser();
void GroupDelUser();

void EnableUserPrivilege();
void DisableUserPrivilege();