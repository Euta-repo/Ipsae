#include "pch.h"
#include "Common.h"
#include "DbInsert.h"
#include "PacketCapture.h"

#define THREAD_COUNT 4

static unsigned int __stdcall WorkerThread(void* param)
{
    THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

    SetEvent(context->hReadyEvent);
    
    return 0;
}

int wmain()
{
	// 콘솔을 UTF-16 모드로 설정 (유니코드 출력 지원)
    //_setmode(_fileno(stdout), _O_U16TEXT);

    /* ============================== */
    // 1. Initialize 작성
    /* ============================== */


    /* ============================== */
    // 2. Flag 초기화 작성
    /* ============================== */


    /* ============================== */
	// 3. Thread 생성 및 초기화
	/* ============================== */

    HANDLE hThreads[THREAD_COUNT] = {};
    THREAD_CONTEXT threadContexts[THREAD_COUNT] = {};
    THREAD_FUNC threadFunctions[THREAD_COUNT] = { 
        WorkerThread,
        StartDbInsertThread, 
        WorkerThread, 
        StartPacketCaptureThread
    };

    for (int i = 0; i < THREAD_COUNT; i++)
    {
		// Thread context 초기화 및 준비 이벤트 생성
        threadContexts[i].ThreadId = i;
        threadContexts[i].hReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

		if (!threadContexts[i].hReadyEvent)
		{
			wprintf(L"[FAIL][main] CreateEventW: error %lu\n", GetLastError());
			for (int j = 0; j < i; j++)
				CloseHandle(threadContexts[j].hReadyEvent);
			return 1;
		}

		// Thread 생성
        hThreads[i] = (HANDLE)_beginthreadex(NULL, 0, threadFunctions[i], &threadContexts[i], 0, NULL);

		// Thread 생성 실패 시 에러 메시지 출력 후 종료
        if (!hThreads[i])
        {
            wprintf(L"[FAIL][main] CreateThread: error %lu\n", GetLastError());
            for (int j = 0; j < i; j++)
                CloseHandle(threadContexts[j].hReadyEvent);
            for (int j = 0; j < i; j++)
                CloseHandle(hThreads[j]);
            return 1;
        }

        // Thread 준비될 때까지 대기 (최대 10초)
        DWORD result = WaitForSingleObject(threadContexts[i].hReadyEvent, 10000);
		CloseHandle(threadContexts[i].hReadyEvent);

        // Thread 준비 실패 시 에러 메시지 출력 후 종료
        if (result != WAIT_OBJECT_0)
        {
            wprintf(L"[FAIL][main] WaitForSingleObject: error %lu\n", GetLastError());
            for (int j = 0; j < i; j++)
                CloseHandle(hThreads[j]);
            return 1;
		}
        
		// 잠시 대기
        Sleep(100);
	}

	// 모든 Thread 종료 대기
    WaitForMultipleObjects(THREAD_COUNT, hThreads, TRUE, INFINITE);

    /* ============================== */
    // 4. 정리 및 종료
    /* ============================== */

    for (int i = 0; i < THREAD_COUNT; i++)
    {
		if (hThreads[i])
            CloseHandle(hThreads[i]);
    }

    wprintf(L"\n[OK][main] Engine 종료\n");
    return 0;
}
