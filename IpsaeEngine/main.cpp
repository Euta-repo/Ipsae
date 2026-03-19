#include "pch.h"
#include "Common.h"
#include "IpcClient.h"
#include "DbInsert.h"
#include "Inspector.h"
#include "PacketCapture.h"

#define THREAD_COUNT 4

/// <summary>
/// 워커 스레드를 생성하고 준비 완료까지 대기합니다.
/// </summary>
/// <returns>모든 스레드 생성 성공 시 true, 실패 시 false</returns>
static bool CreateWorkerThreads(ENGINE_STATE& state, HANDLE* hThreads, THREAD_FUNC* funcs, int count)
{
    THREAD_CONTEXT contexts[THREAD_COUNT] = {};

    for (int i = 0; i < count; i++)
    {
        contexts[i].ThreadId = i;
        contexts[i].hReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        contexts[i].state = &state;

        if (!contexts[i].hReadyEvent)
        {
            spdlog::error("[FAIL][main] CreateEventW: error {}", GetLastError());
            for (int j = 0; j < i; j++)
                CloseHandle(contexts[j].hReadyEvent);
            return false;
        }

        hThreads[i] = (HANDLE)_beginthreadex(NULL, 0, funcs[i], &contexts[i], 0, NULL);

        if (!hThreads[i])
        {
            spdlog::error("[FAIL][main] CreateThread: error {}", GetLastError());
            for (int j = 0; j <= i; j++)
                CloseHandle(contexts[j].hReadyEvent);
            for (int j = 0; j < i; j++)
                CloseHandle(hThreads[j]);
            return false;
        }

        DWORD result = WaitForSingleObject(contexts[i].hReadyEvent, 10000);
        CloseHandle(contexts[i].hReadyEvent);

        if (result != WAIT_OBJECT_0)
        {
            spdlog::error("[FAIL][main] WaitForSingleObject: error {}", GetLastError());
            for (int j = 0; j <= i; j++)
                CloseHandle(hThreads[j]);
            return false;
        }
    }

    return true;
}

/// <summary>
/// 모든 모듈이 Running 상태가 될 때까지 대기합니다.
/// </summary>
/// <returns>모든 모듈 준비 완료 시 true, 실패 시 false</returns>
static bool WaitForModulesReady(ENGINE_STATE& state)
{
    Sleep(500);

    int failCount = 0;
    while (state.dbInsertRunning == false || state.inspectorRunning == false ||
        state.ipcClientRunning == false || state.packetCaptureRunning == false)
    {
        if (state.status == STATUS_ERROR)
        {
            spdlog::error("[main] Thread 초기화 실패: 일부 모듈이 오류 상태입니다.");
            return false;
        }

        if (failCount > 3)
        {
            spdlog::warn("[main] Thread 초기화 실패: 실패 횟수가 중첩되어 엔진을 종료합니다.");
            state.status = STATUS_ERROR;
            return false;
        }

        spdlog::warn("[main] Thread 초기화 실패: 일부 모듈이 준비되지 않았습니다.");
        failCount++;
        Sleep(1000);
    }

    return true;
}

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
    if (state.config.logPath.empty())  state.config.logPath  = "C:\\Ipsae\\logs";
    if (state.config.dbPath.empty())   state.config.dbPath   = "C:\\Ipsae\\Config\\ipsaedb.db";
    if (state.config.iniPath.empty())  state.config.iniPath  = "C:\\Ipsae\\Config\\config.ini";
    if (state.config.pipeName.empty()) state.config.pipeName = "IpsaeEngine";

    InitializeLogger(state.config.logPath);

	state.config.interfaceName = GetConfigValues(state.config.iniPath);

    spdlog::info("[main] DB:   {}", state.config.dbPath);
    spdlog::info("[main] INI:  {}", state.config.iniPath);
    spdlog::info("[main] Pipe: {}", state.config.pipeName);
    spdlog::info("[main] Interface: {}", state.config.interfaceName);

    /* ============================== */
    // 3. Thread 생성 및 초기화
    /* ============================== */
    HANDLE hThreads[THREAD_COUNT] = {};
    THREAD_FUNC threadFunctions[THREAD_COUNT] = {
        StartIpcClientThread,
        StartDbInsertThread,
        StartInspectorThread,
        StartPacketCaptureThread
    };

    if (CreateWorkerThreads(state, hThreads, threadFunctions, THREAD_COUNT)
        && WaitForModulesReady(state))
    {
        state.status = STATUS_ACTIVE;
        spdlog::info("[main] Engine이 활성화되었습니다.");

        WaitForMultipleObjects(THREAD_COUNT, hThreads, TRUE, INFINITE);
    }

    /* ============================== */
    // 4. 정리 및 종료
    /* ============================== */
    for (int i = 1; i < THREAD_COUNT; i++)
    {
        if (hThreads[i])
            CloseHandle(hThreads[i]);
    }

    int ipcFailCount = 0;
    while (state.ipcClientRunning)
    {
        if (ipcFailCount > 10)
        {
            spdlog::warn("[main] IPC 모듈 종료 대기 실패: 실패 횟수가 중첩되어 엔진을 강제 종료합니다.");
            break;
        }
        spdlog::warn("[main] IPC 모듈이 아직 종료되지 않았습니다. 대기 중...");
        ipcFailCount++;
        Sleep(1000);
    }

    if (hThreads[0] != NULL)
        CloseHandle(hThreads[0]);

    spdlog::info("[main] Engine 종료");
    return 0;
}
