#pragma once
#include "Common.h"


/// <summary>
/// 패킷 캡처를 중지합니다.
/// </summary>
/// <param name="caller">호출자 이름</param>
void StopPacketCapture(const char* caller);

/// <summary>
/// 패킷 캡처 스레드를 시작합니다.
/// </summary>
/// <param name="param">스레드 컨텍스트</param>
/// <returns>스레드 종료 코드</returns>
unsigned int __stdcall StartPacketCaptureThread(void* param);

// 메모
// Inspector에서 위협 DB를 조회할 때 DbInsertThread에 요청?
// 아니면 그냥 DBInsertThread에서 조회?