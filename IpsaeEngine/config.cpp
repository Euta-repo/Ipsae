#include "pch.h"
#include <windows.h>
#include <string>
#include <cstdlib>

using namespace std;

string iniInterfaceParser()
{
	char interfaceOutput[256] = {};
	string iniPath = "C:\\Ipsae\\config.ini";

	GetPrivateProfileStringA("Engine", "Interface", "", interfaceOutput, sizeof(interfaceOutput), iniPath.c_str());

	if (interfaceOutput[0] == '\0')
	{
		MessageBoxA(NULL, "Failed to load interface from config.ini", "오류", MB_OK | MB_ICONERROR);
		return "";
	}

	return interfaceOutput;
}