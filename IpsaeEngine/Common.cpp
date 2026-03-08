#include "pch.h"
#include "Common.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>


// =============================================================================================
// Common functions
// =============================================================================================

void InitializeLogger()
{
	CreateDirectoryA("logs", NULL);

	auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/ipsae.log", 1024 * 1024 * 5, 3);

	auto logger = std::make_shared<spdlog::logger>("ipsae", spdlog::sinks_init_list{ console_sink, file_sink });
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
	if (state->status != ENGINE_WAITING)
		return true;

	DWORD64 waitStart = GetTickCount64();

	while (state->status == ENGINE_WAITING)
	{
		if (GetTickCount64() - waitStart > TIMEOUT_WAITING)
		{
			spdlog::warn("[{}] Waiting 상태 지연으로 작업을 중단합니다.", caller);
			state->status = ENGINE_ERROR;
			return false;
		}
		Sleep(100);
	}
	return true;
}
