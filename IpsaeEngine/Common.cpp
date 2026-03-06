#include "Common.h"


// =============================================================================================
// Common functions
// =============================================================================================

/// <summary>
/// 엔진이 WAITING 상태일 때 타임아웃까지 대기합니다.
/// </summary>
/// <param name="state">엔진 상태 포인터</param>
/// <param name="caller">호출자 모듈명 (로그용)</param>
/// <returns>대기 해제 시 true, 타임아웃 시 false (ENGINE_ERROR로 전환됨)</returns>
inline bool WaitForEngineWaiting(ENGINE_STATE* state, const wchar_t* caller)
{
	if (state->status != ENGINE_WAITING)
		return true;

	DWORD64 waitStart = GetTickCount64();

	while (state->status == ENGINE_WAITING)
	{
		if (GetTickCount64() - waitStart > TIMEOUT_WAITING)
		{
			wprintf(L"[WARN][%s] Waiting 상태 지연으로 작업을 중단합니다.\n", caller);
			state->status = ENGINE_ERROR;
			return false;
		}
		Sleep(100);
	}
	return true;
}