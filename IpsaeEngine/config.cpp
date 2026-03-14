#include "pch.h"
#include <windows.h>
#include <string>
#include <cstdlib>

using namespace std;

string iniInterfaceParser()
{
	char interfaceOutput[256] = {};
	string userName = getenv("USERPROFILE");

	if (userName.empty())
	{
		MessageBoxA(NULL, "USERPROFILE 환경 변수를 가져오는 데 실패했습니다.", "오류", MB_OK | MB_ICONERROR);
		return "";
	}

	userName += "\\Documents\\Codes\\Ipsae\\IpsaeEngine\\x64\\Debug\\config.ini";

	GetPrivateProfileStringA("Engine", "Interface", "", interfaceOutput, sizeof(interfaceOutput), userName.c_str());

	if (interfaceOutput[0] == '\0')
	{
		MessageBoxA(NULL, "Failed to load interface from config.ini", "오류", MB_OK | MB_ICONERROR);
		return "";
	}

	return interfaceOutput;
}