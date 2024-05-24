//Задача:
//Реализовать программу для управления учетными записями и контролем
//доступа в ОС Windows, использующую возможности Windows API.

//Требования :
//- язык программирования : C / C++;
//- динамическая подгрузка библиотек Windows, реализующих функции Windows API;
//- разрабатываемая программа не должна использовать готовые обертки над Windows API;
//- программа должна выводить списки зарегистрированных в системе пользователей и групп, их SID и привилегии;
//- программа должна позволять добавлять / изменять / удалять пользователей и группы в ОС, а также удалять и добавлять, включать и выключать им привилегии;
//- программа должна в ОС Windows 7 – 10.

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