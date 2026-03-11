#include "pch.h"
#include "IpcTool.h"

#pragma region Constants

// IpsaeService(C# Named Pipe 서버)와 통신할 때 사용하는 파이프 이름
// PipeProtocol.cs의 PipeName = "IpsaeIDS" 와 동일해야 함
static const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\IpsaeIDS";

// 파이프 연결 시 최대 대기 시간 (밀리초)
static const DWORD PIPE_CONNECT_TIMEOUT = 3000;

// 파이프 메시지의 최대 페이로드 크기 (바이트)
// PipeMessage.cs에서 payloadLength > 1024 * 64 로 검증하므로 동일하게 맞춤
static const int MAX_PAYLOAD_SIZE = 1024 * 64;

// ──────────────────────────────────────────────────────────────────────
// 파이프 프로토콜 상수 (PipeProtocol.cs / PipeMessage.cs 와 1:1 대응)
// ──────────────────────────────────────────────────────────────────────

// 메시지 헤더 크기: Command(1바이트) + PayloadLength(4바이트) = 5바이트
static const int HEADER_SIZE = 5;

// ── PipeCommand (Client -> Service) ──
static const BYTE CMD_QUERY_STATUS = 0x01;  // 현재 서비스 상태 조회
static const BYTE CMD_START_SERVICE = 0x02; // 서비스 시작 요청
static const BYTE CMD_STOP_SERVICE = 0x03;  // 서비스 중지 요청

// ── PipeCommand (Service -> Client) ──
static const BYTE CMD_STATUS_RESPONSE = 0x81; // 상태 응답

// ── ServiceStatusCode ──
static const BYTE STATUS_ACTIVE   = 0x00; // 서비스 실행 중
static const BYTE STATUS_INACTIVE = 0x01; // 서비스 중지됨
static const BYTE STATUS_STARTING = 0x02; // 서비스 시작 중
static const BYTE STATUS_STOPPING = 0x03; // 서비스 중지 중

// 엔진 상태를 주기적으로 서비스에 보고하는 간격 (밀리초)
static const DWORD REPORT_INTERVAL = 5000;

#pragma endregion

#pragma region Forward declaration

static unsigned int StartIpcTool(HANDLE hReadyEvent, ENGINE_STATE* state);
static HANDLE ConnectToPipe();
static int SendCommand(HANDLE hPipe, BYTE command);
static int ReadResponse(HANDLE hPipe, BYTE* outCommand, std::vector<BYTE>& outPayload);
static int QueryServiceStatus(HANDLE hPipe, BYTE* outStatus);

#pragma endregion

#pragma region Functions

unsigned int __stdcall StartIpcToolThread(void* param)
{
    THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

    return StartIpcTool(context->hReadyEvent, context->state);
}

#pragma endregion

#pragma region Static functions

static void StopIpcTool(HANDLE hPipe, ENGINE_STATE* state)
{
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    state->ipcToolRunning = false;
}

static HANDLE ConnectToPipe()
{
	// 첫 번째 시도: 파이프에 즉시 연결 시도
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,                          // 파이프 경로 (\\.\pipe\IpsaeIDS)
        GENERIC_READ | GENERIC_WRITE,       // 읽기/쓰기 양방향 접근
        0,                                  // 공유 모드 없음 (단독 접근)
        NULL,                               // 기본 보안 속성
        OPEN_EXISTING,                      // 기존 파이프에 연결
        0,                                  // 동기 I/O (플래그 없음)
        NULL);                              // 템플릿 파일 없음

    // 연결 성공 시 즉시 반환
    if (hPipe != INVALID_HANDLE_VALUE)
        return hPipe;

	// 연결 실패 시 오류 코드 확인
    DWORD err = GetLastError();
    if (err != ERROR_PIPE_BUSY)
    {
        spdlog::warn("[IpcTool] ConnectToPipe: 파이프를 찾을 수 없습니다. (error {})", err);
        return INVALID_HANDLE_VALUE;
    }

	// 첫 번째 시도: 파이프가 현재 사용 중이므로 대기
    if (!WaitNamedPipeW(PIPE_NAME, PIPE_CONNECT_TIMEOUT))
    {
        spdlog::warn("[IpcTool] ConnectToPipe: 파이프 대기 시간 초과");
        return INVALID_HANDLE_VALUE;
    }

    // 2차 시도: 대기 후 파이프 인스턴스가 사용 가능해졌으므로 재연결
    hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

	// 2차 시도 결과 반환 (성공 또는 실패)
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        spdlog::warn("[IpcTool] ConnectToPipe: 2차 연결 실패 (error {})", GetLastError());
    }

    return hPipe;
}

static int SendCommand(HANDLE hPipe, BYTE command)
{
	// 파이프 메시지 버퍼: 페이로드(1바이트) + 헤더(4바이트)
    BYTE buffer[HEADER_SIZE] = {};

    // 첫 번째 바이트: 명령 코드 (예: 0x01 = QueryStatus)
    buffer[0] = command;

    // 2~5번째 바이트: 페이로드 길이 = 0 (리틀엔디안 INT32)
    // 모든 바이트가 이미 0으로 초기화되어 있으므로 별도 설정 불필요
    // buffer[1..4] = 0x00 0x00 0x00 0x00 → PayloadLength = 0

    // WriteFile로 동기 쓰기 수행
    DWORD written = 0;
    if (!WriteFile(hPipe, buffer, HEADER_SIZE, &written, NULL))
    {
        spdlog::error("[IpcTool] SendCommand: 파이프 쓰기 실패 (error {})", GetLastError());
        return 1;
    }

    // 버퍼에 남아있는 데이터를 즉시 전송
    // 서버 측(C#)에서 ReadAsync가 블로킹 중이므로 Flush하지 않으면 데이터가 지연될 수 있음
    FlushFileBuffers(hPipe);
    return 0;
}


static int ReadResponse(HANDLE hPipe, BYTE* outCommand, std::vector<BYTE>& outPayload)
{
    // ── 1단계: 헤더 5바이트 읽기 ──
    BYTE header[HEADER_SIZE] = {};
    DWORD totalRead = 0;

    // ReadFile이 요청한 바이트 수보다 적게 반환할 수 있으므로
    // 5바이트를 모두 읽을 때까지 반복 (스트림 기반 I/O의 일반적 패턴)
    while (totalRead < HEADER_SIZE)
    {
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, header + totalRead, HEADER_SIZE - totalRead, &bytesRead, NULL))
        {
            spdlog::error("[IpcTool] ReadResponse: 헤더 읽기 실패 (error {})", GetLastError());
            return 1;
        }

        // bytesRead == 0 이면 서버가 연결을 끊은 것 (EOF)
        if (bytesRead == 0)
        {
            spdlog::warn("[IpcTool] ReadResponse: 서버 연결 끊김 (EOF)");
            return 1;
        }

        totalRead += bytesRead;
    }

    // ── 헤더 파싱 ──
    // 첫 바이트: 명령 코드
    *outCommand = header[0];

    // 2~5번째 바이트: 페이로드 길이 (리틀엔디안 INT32)
    // C#의 BitConverter.ToInt32(header, 1)과 동일한 동작
    // memcpy를 사용하는 이유: header+1 주소는 4바이트 정렬(alignment)이
    // 보장되지 않으므로, 직접 (int*) 캐스팅하면 일부 아키텍처에서
    // 정렬 위반(unaligned access) 오류가 발생할 수 있다.
    int payloadLength = 0;
    memcpy(&payloadLength, header + 1, sizeof(int));

    // ── 페이로드 유효성 검사 ──
    // PipeMessage.cs의 검증 로직과 동일: 음수이거나 64KB 초과 시 거부
    if (payloadLength < 0 || payloadLength > MAX_PAYLOAD_SIZE)
    {
        spdlog::error("[IpcTool] ReadResponse: 잘못된 페이로드 크기 ({})", payloadLength);
        return 1;
    }

    // ── 2단계: 페이로드 읽기 ──
    outPayload.clear();

    // 페이로드가 없는 경우 (예: 일부 에러 응답) 바로 성공 반환
    if (payloadLength == 0)
        return 0;

    // 페이로드 버퍼 할당 및 스트림 읽기
    outPayload.resize(payloadLength);
    totalRead = 0;

    while (totalRead < (DWORD)payloadLength)
    {
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, outPayload.data() + totalRead, payloadLength - totalRead, &bytesRead, NULL))
        {
            spdlog::error("[IpcTool] ReadResponse: 페이로드 읽기 실패 (error {})", GetLastError());
            return 1;
        }

        if (bytesRead == 0)
        {
            spdlog::warn("[IpcTool] ReadResponse: 페이로드 읽기 중 서버 연결 끊김");
            return 1;
        }

        totalRead += bytesRead;
    }

    return 0;
}


static int QueryServiceStatus(HANDLE hPipe, BYTE* outStatus)
{
    // 상태 조회 명령 전송
    if (SendCommand(hPipe, CMD_QUERY_STATUS) != 0)
        return 1;

    // 서버 응답 수신
    BYTE responseCommand = 0;
    std::vector<BYTE> payload;

    if (ReadResponse(hPipe, &responseCommand, payload) != 0)
        return 1;

    // ── 응답 검증 ──
    // 1) 명령 코드가 StatusResponse(0x81)인지 확인
    if (responseCommand != CMD_STATUS_RESPONSE)
    {
        spdlog::error("[IpcTool] QueryServiceStatus: 예상과 다른 응답 명령 (0x{:02X})", responseCommand);
        return 1;
    }

    // 2) 페이로드가 최소 1바이트 이상인지 확인
    //    PipeMessage.Status()는 항상 1바이트 페이로드를 포함함
    if (payload.empty())
    {
        spdlog::error("[IpcTool] QueryServiceStatus: 빈 페이로드");
        return 1;
    }

    // 페이로드의 첫 바이트가 ServiceStatusCode
    *outStatus = payload[0];
    return 0;
}


/// <summary>
/// 로그 출력을 위해 ServiceStatusCode를 문자열로 변환한다.
/// </summary>
/// <param name="status">ServiceStatusCode</param>
/// <returns>문자열로 변환된 상태</returns>
static const char* StatusCodeToString(BYTE status)
{
    switch (status)
    {
    case STATUS_ACTIVE:   return "Active";
    case STATUS_INACTIVE: return "Inactive";
    case STATUS_STARTING: return "Starting";
    case STATUS_STOPPING: return "Stopping";
    default:              return "Unknown";
    }
}


// ──────────────────────────────────────────────────────────────────────
// StartIpcTool
// IPC 모듈의 메인 루프. 주기적으로 IpsaeService와 통신하여
// 서비스 상태를 모니터링한다.
//
// [동작 흐름]
// 1. Named Pipe로 IpsaeService에 연결
// 2. Main 스레드에 준비 완료 시그널 전송 (SetEvent)
// 3. 메인 루프:
//    a. 엔진 대기 상태(ENGINE_WAITING) 처리
//    b. 엔진 오류/종료 상태 확인
//    c. 서비스 상태 질의 (QueryServiceStatus)
//    d. 연결 끊김 시 자동 재연결 (서비스 재시작 등의 상황 대응)
//    e. REPORT_INTERVAL만큼 Sleep
// 4. 종료 시 파이프 핸들 정리
//
// hReadyEvent: main.cpp에서 생성한 이벤트. 초기화 완료 시 시그널
// state: 엔진 전체 상태를 공유하는 구조체 포인터
// 반환값: 0 = 정상 종료, 1 = 초기화 실패
// ──────────────────────────────────────────────────────────────────────
static unsigned int StartIpcTool(HANDLE hReadyEvent, ENGINE_STATE* state)
{
    // IpsaeService의 Named Pipe 서버에 연결 시도
    HANDLE hPipe = ConnectToPipe();

    // 연결 실패해도 스레드는 시작 → 메인 루프에서 재연결을 시도
    // (서비스가 아직 시작되지 않았을 수 있으므로 여기서 종료하지 않음)
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        spdlog::warn("[IpcTool] 초기 파이프 연결 실패. 메인 루프에서 재연결을 시도합니다.");
    }
    else
    {
        spdlog::info("[IpcTool] 파이프 연결 성공");
    }

    // Main 스레드에게 이 스레드가 준비되었음을 알림
    state->ipcToolRunning = true;
    SetEvent(hReadyEvent);

    spdlog::info("[IpcTool] IPC 모듈 시작");

    // ── 메인 루프 ──
    // 엔진이 STOPPING/STOPPED/ERROR 상태가 될 때까지 반복
    while (state->status != ENGINE_STOPPING &&
           state->status != ENGINE_STOPPED &&
           state->status != ENGINE_ERROR)
    {
        // ── 엔진 대기 상태 처리 ──
        // ENGINE_WAITING 상태이면 상태가 바뀔 때까지 블로킹 대기
        // 타임아웃(60초) 초과 시 false 반환 → 루프 탈출
        if (!WaitForEngineWaiting(state, "IpcTool"))
            break;

        // ── 파이프 미연결 상태 → 재연결 시도 ──
        // 서비스가 재시작되었거나, 이전 연결이 끊긴 경우 여기서 복구
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            hPipe = ConnectToPipe();
            if (hPipe == INVALID_HANDLE_VALUE)
            {
                // 연결 실패 → 다음 주기에 다시 시도
                Sleep(REPORT_INTERVAL);
                continue;
            }
            spdlog::info("[IpcTool] 파이프 재연결 성공");
        }

        // ── 서비스 상태 질의 ──
        BYTE serviceStatus = 0;
        if (QueryServiceStatus(hPipe, &serviceStatus) != 0)
        {
            // 통신 실패 → 파이프 연결이 끊긴 것으로 간주
            // 핸들을 닫고 다음 루프에서 재연결 시도
            spdlog::warn("[IpcTool] 서비스 상태 질의 실패. 파이프를 닫고 재연결합니다.");
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;

            Sleep(REPORT_INTERVAL);
            continue;
        }

        // 서비스 상태 로그 출력
        spdlog::debug("[IpcTool] 서비스 상태: {}", StatusCodeToString(serviceStatus));

        // ── 다음 질의까지 대기 ──
        // REPORT_INTERVAL(5초)마다 서비스 상태를 확인
        // Sleep 중에는 엔진 상태 변화를 감지하지 못하므로
        // 긴급 종료가 필요하면 WaitForEngineWaiting에서 처리됨
        Sleep(REPORT_INTERVAL);
    }

    // ── 종료 처리 ──
    spdlog::info("[IpcTool] IPC 모듈 종료");
    StopIpcTool(hPipe, state);
    return 0;
}

#pragma endregion
