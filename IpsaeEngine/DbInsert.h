#pragma once
#include "Common.h"
#include "Models.h"

/// <summary>
/// DB 삽입 스레드를 시작합니다.
/// </summary>
/// <param name="param">스레드 컨텍스트</param>
/// <returns>스레드 종료 코드</returns>
unsigned int __stdcall StartDbInsertThread(void* param);


/// <summary>
/// 데이터베이스 삽입 작업을 큐에 추가합니다.
/// </summary>
/// <param name="data">큐에 추가할 데이터베이스 삽입 배치 데이터</param>
void EnqueueDbInsert(const DB_INSERT_BATCH& data);