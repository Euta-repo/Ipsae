#include "pch.h"
#include "Common.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <windows.h>


// =============================================================================================
// Common functions
// =============================================================================================

/// <summary>
/// 로거를 초기화하고 콘솔 및 파일 출력을 설정합니다.
/// </summary>
void InitializeLogger(std::string logPath)
{
	std::string dirPath = logPath.substr(0, logPath.find_last_of("\\/"));
	std::string filename = logPath.substr(logPath.find_last_of("\\/") + 1);

	CreateDirectoryA(dirPath.c_str(), NULL);

	auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logPath, 1024 * 1024 * 5, 3);

	auto logger = std::make_shared<spdlog::logger>(filename, spdlog::sinks_init_list{ console_sink, file_sink });
	logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
	logger->set_level(spdlog::level::trace);

	spdlog::set_default_logger(logger);
	spdlog::flush_every(std::chrono::seconds(3));
}

/// <summary>
/// 엔진이 WAITING 상태일 때 타임아웃까지 대기합니다.
/// </summary>
/// <param name="state">엔진 상태 포인터</param>
/// <param name="caller">호출자 모듈명 (로그용)</param>
/// <returns>대기 해제 시 true, 타임아웃 시 false (ENGINE_ERROR로 전환됨)</returns>
bool WaitForEngineWaiting(ENGINE_STATE* state, const char* caller)
{
	if (state->status != STATUS_WAITING)
		return true;

	DWORD64 waitStart = GetTickCount64();

	while (state->status == STATUS_WAITING)
	{
		if (GetTickCount64() - waitStart > TIMEOUT_WAITING)
		{
			spdlog::warn("[{}] Waiting 상태 지연으로 작업을 중단합니다.", caller);
			state->status = STATUS_ERROR;
			return false;
		}
		Sleep(100);
	}
	return true;
}

/// <summary>
/// IP 주소를 문자열로 변환합니다.
/// </summary>
/// <param name="ip">변환할 IP 주소 (32비트 정수).</param>
/// <param name="buf">결과 문자열을 저장할 버퍼.</param>
/// <param name="bufLen">버퍼의 크기 (바이트 단위).</param>
void IpToStr(UINT32 ip, char* buf, size_t bufLen)
{
	UINT8* b = (UINT8*)&ip;
	sprintf_s(buf, bufLen, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/// <summary>
/// 문자열을 IP 주소로 변환합니다.
/// </summary>
/// <param name="str">변환할 문자열 (예: "192.168.0.1").</param>
/// <returns>변환된 IP 주소 (32비트 정수).</returns>
UINT32 StrToIp(const char* str)
{
	UINT8 b[4];
	sscanf_s(str, "%hhu.%hhu.%hhu.%hhu", &b[0], &b[1], &b[2], &b[3]);
	return *(UINT32*)b;
}


/// <summary>
/// INI 파일에서 네트워크 인터페이스 이름을 읽어옵니다.
/// </summary>
std::string GetConfigValues(const std::string iniPath)
{
	char interfaceOutput[256] = {};

	GetPrivateProfileStringA("Engine", "Interface", "", interfaceOutput, sizeof(interfaceOutput), iniPath.c_str());

	if (interfaceOutput[0] == '\0')
	{
		spdlog::error("[Common] Failed to load interface from config.ini");
		return "";
	}

	return interfaceOutput;
}


/// <summary>
/// 커맨드라인 파라미터를 파싱하여 ENGINE_STATE에 저장합니다.
/// 사용법: IpsaeEngine.exe --db "경로" --ini "경로" --pipe "파이프명"
/// </summary>
void ParseArguments(int argc, wchar_t* argv[], ENGINE_STATE& state)
{
	for (int i = 1; i < argc; i++)
	{
		if (wcscmp(argv[i], L"--db") == 0 && i + 1 < argc)
		{
			char buf[MAX_PATH];
			WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, buf, MAX_PATH, NULL, NULL);
			state.config.dbPath = buf;
		}
		else if (wcscmp(argv[i], L"--ini") == 0 && i + 1 < argc)
		{
			char buf[MAX_PATH];
			WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, buf, MAX_PATH, NULL, NULL);
			state.config.iniPath = buf;
		}
		else if (wcscmp(argv[i], L"--pipe") == 0 && i + 1 < argc)
		{
			char buf[256];
			WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, buf, 256, NULL, NULL);
			state.config.pipeName = buf;
		}
		else if (wcscmp(argv[i], L"--log") == 0 && i + 1 < argc)
		{
			char buf[256];
			WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, buf, 256, NULL, NULL);
			state.config.logPath = buf;
		}
	}
}
