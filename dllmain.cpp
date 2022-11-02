#include "pch.h"
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

#pragma warning(disable:4996 4715)

bool INT_ComparePattern(char* szSource, const char* szPattern, const char* szMask)
{
	for (; *szMask; ++szSource, ++szPattern, ++szMask)
		if (*szMask == 'x' && *szSource != *szPattern)
			return false;
	return true;
}

char* INT_PatternScan(char* pData, UINT_PTR RegionSize, const char* szPattern, const char* szMask, int Len)
{
	for (UINT i = 0; i != RegionSize - Len; ++i, ++pData)
		if (INT_ComparePattern(pData, szPattern, szMask))
			return pData;
	return nullptr;
}

char* PatternScan(char* pStart, UINT_PTR RegionSize, const char* szPattern, const char* szMask)
{
	char* pCurrent = pStart;
	auto Len = lstrlenA(szMask);

	while (pCurrent <= pStart + RegionSize - Len)
	{
		MEMORY_BASIC_INFORMATION MBI{ 0 };
		if (!VirtualQuery(pCurrent, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
			return nullptr;

		if (MBI.State == MEM_COMMIT && !(MBI.Protect & PAGE_NOACCESS))
		{
			if (pCurrent + MBI.RegionSize > pStart + RegionSize - Len)
				MBI.RegionSize = pStart + RegionSize - pCurrent + Len;

			char* Ret = INT_PatternScan(pCurrent, MBI.RegionSize, szPattern, szMask, Len);

			if (Ret)
				return Ret;
		}
		pCurrent += MBI.RegionSize;
	}

	return nullptr;
}

void Scan()
{
	printf("Printed Pointer: %X\n", PatternScan(nullptr, (UINT_PTR)-1, 
		"\x3B\x47\x5C\x0F\x84\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x3B\x47\x5C\x75\x0D\x80\xBF\x2A\", 
		"xxxxxxxx????xxxxxxxxx????x??"));
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		system("cls");
		Scan();
		freopen("CONOUT$", "w", stdout);
		break;
	}
	return TRUE;
}