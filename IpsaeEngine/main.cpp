#include "pch.h"
#include "Common.h"
#include "IpcClient.h"
#include "DbInsert.h"
#include "Inspector.h"
#include "PacketCapture.h"

#define THREAD_COUNT 4

int wmain(int argc, wchar_t* argv[])
{
    /* ============================== */
    // 1. Initialize
    /* ============================== */
    ENGINE_STATE state;
    state.status = STATUS_INIT;

    SetConsoleOutputCP(CP_UTF8);
    ParseArguments(argc, argv, state);

    state.status = STATUS_STARTING;

    /* ============================== */
    // 2. Config Load
    /* ============================== */
    // 파라미터가 없으면 기본값 사용
    if (state.config.logPath.empty())  state.config.logPath  = "C:\\Ipsae\\logs";
    if (state.config.dbPath.empty())   state.config.dbPath   = "C:\\Ipsae\\Config\\ipsaedb.db";
    if (state.config.iniPath.empty())  state.config.iniPath  = "C:\\Ipsae\\Config\\config.ini";
    if (state.config.pipeName.empty()) state.config.pipeName = "IpsaeEngine";

    InitializeLogger(state.config.logPath);

	state.config.interfaceName = GetConfigValues(state.config.iniPath);

	// 로드된 설정값 로그 출력
    spdlog::info("[main] DB:   {}", state.config.dbPath);
    spdlog::info("[main] INI:  {}", state.config.iniPath);
    spdlog::info("[main] Pipe: {}", state.config.pipeName);
    spdlog::info("[main] Interface: {}", state.config.interfaceName);

    /* ============================== */
    // 3. Thread 생성 및 초기화
    /* ============================== */

    HANDLE hThreads[THREAD_COUNT] = {};
    THREAD_CONTEXT threadContexts[THREAD_COUNT] = {};
    THREAD_FUNC threadFunctions[THREAD_COUNT] = {
        StartIpcClientThread,
        StartDbInsertThread,
        StartInspectorThread,
        StartPacketCaptureThread
    };

    for (int i = 0; i < THREAD_COUNT; i++)
    {
        // Thread context 초기화 및 준비 이벤트 생성
        threadContexts[i].ThreadId = i;
        threadContexts[i].hReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        threadContexts[i].state = &state;

        if (!threadContexts[i].hReadyEvent)
        {
            spdlog::error("[FAIL][main] CreateEventW: error {}", GetLastError());
            for (int j = 0; j < i; j++)
                CloseHandle(threadContexts[j].hReadyEvent);

			state.status = STATUS_ERROR;
            break;
        }

        // Thread 생성
        hThreads[i] = (HANDLE)_beginthreadex(NULL, 0, threadFunctions[i], &threadContexts[i], 0, NULL);

        // Thread 생성 실패 시 에러 메시지 출력 후 종료
        if (!hThreads[i])
        {
            spdlog::error("[FAIL][main] CreateThread: error {}", GetLastError());
            for (int j = 0; j < i; j++)
                CloseHandle(threadContexts[j].hReadyEvent);
            for (int j = 0; j < i; j++)
                CloseHandle(hThreads[j]);
            
			state.status = STATUS_ERROR;
			break;
        }

        // Thread 준비될 때까지 대기 (최대 10초)
        DWORD result = WaitForSingleObject(threadContexts[i].hReadyEvent, 10000);
        CloseHandle(threadContexts[i].hReadyEvent);

        // Thread 준비 실패 시 에러 메시지 출력 후 종료
        if (result != WAIT_OBJECT_0)
        {
            spdlog::error("[FAIL][main] WaitForSingleObject: error {}", GetLastError());
            for (int j = 0; j < i; j++)
                CloseHandle(hThreads[j]);

            state.status = STATUS_ERROR;
            break;
        }
    }

    // 잠시 대기
    Sleep(500);

    // 전체 상태 검사
    int failCount = 0;
    while(state.dbInsertRunning == false || state.inspectorRunning == false || 
        state.ipcClientRunning == false || state.packetCaptureRunning == false)
    {
        if (state.status == STATUS_ERROR)
        {
            spdlog::error("[main] Thread 초기화 실패: 일부 모듈이 오류 상태입니다.");
            break;
		}

        if (failCount > 3)
        {
            spdlog::warn("[main] Thread 초기화 실패: 실패 횟수가 중첩되어 엔진을 종료합니다.");
            state.status = STATUS_ERROR;
            break;
        }

        spdlog::warn("[main] Thread 초기화 실패: 일부 모듈이 준비되지 않았습니다.");
        failCount++;
        Sleep(1000);
    }

	// 초기화 실패 시 엔진 종료
    if (state.status == STATUS_ERROR)
		goto SYSEND;

	// 모든 모듈이 준비되었으므로 엔진 활성화
	state.status = STATUS_ACTIVE;
    spdlog::info("[main] Engine이 활성화되었습니다.");

    // 모든 Thread 종료 대기
    WaitForMultipleObjects(THREAD_COUNT, hThreads, TRUE, INFINITE);

    /* ============================== */
    // 4. 정리 및 종료
    /* ============================== */

SYSEND:
	for (int i = 1; i < THREAD_COUNT; i++) // 첫 번째 스레드는 IpcClient이므로 마지막에 종료되도록 대기
    {
        if (hThreads[i])
            CloseHandle(hThreads[i]);
    }

    while (state.ipcClientRunning) // IpcClient이 먼저 종료되지 않았으면 대기
    {
        spdlog::warn("[main] IPC 모듈이 아직 종료되지 않았습니다. 대기 중...");
        Sleep(1000);
	}

    if (hThreads[0] != NULL) // IpcClient 스레드 종료 대기
		CloseHandle(hThreads[0]);

    spdlog::info("[main] Engine 종료");
    return 0;
}
