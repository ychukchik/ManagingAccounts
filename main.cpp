#define _CRT_SECURE_NO_WARNINGS
#pragma once

#include "settings.h"

int CheckEnter(int input);

int main()
{
	setlocale(LC_CTYPE, "rus");
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	printf(">>>Управление учетными записями и контроль доступа<<<\n\n");

	//LPCWSTR username = L"aoaoao";
	//LPCWSTR privilege = SE_BACKUP_NAME; // Example privilege, replace with desired one

	// Подгрузка библиотек
	LoadAllLibs();
	// Получение указателей на функции, экспортируемые netapi32.dll и advapi32.dll	
	GetFuncs();

	int input;
	// Вывод списка команд и считывание команды
	while (1)
	{
		Help();
		scanf_s("%d", &input);
		input = CheckEnter(input);
		printf("\n");

		if (input == -1) { printf("Некорректный ввод\n"); }
		else if (input == 0) { break; }		
		else if (input == 1) { UsersList(); }
		else if (input == 2) { UserAdd(); }
		else if (input == 3) { UserDelete(); }
		else if (input == 4) { UserChangePassword(); }
		else if (input == 5) { UserAddPrivilege(); }
		else if (input == 6) { UserDelPrivilege(); }
		else if (input == 7) { GroupList(); }
		else if (input == 8) { GroupAdd(); }
		else if (input == 9) { GroupDelete(); }
		else if (input == 10) { GroupAddUser(); }
		else if (input == 11) { GroupDelUser(); }
		else if (input == 12) { GroupAddPrivilege(); }
		else if (input == 13) { GroupDelPrivilege(); }
		else if (input == 14) { EnableUserPrivilege(); }
		else if (input == 15) { DisableUserPrivilege(); }

	}
	FreeAllLibs();
	return 0;
}