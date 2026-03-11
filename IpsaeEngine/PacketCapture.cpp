#include "pch.h"
#include "PacketCapture.h"
#include <windivert.h>

#pragma comment(lib, "WinDivert.lib")

#pragma region Variables

#define PACKET_BUFSIZE  0xFFFF // 최대 패킷 크기 (65535 바이트)

static std::atomic<bool> s_running{ false };

static HANDLE s_handle = INVALID_HANDLE_VALUE;

static ThreadSafeQueue<std::unordered_set<UINT32>> s_sampleQueue;

#pragma endregion

#pragma region Forward declaration

static unsigned int StartPacketCapture(HANDLE hReadyEvent, ENGINE_STATE* state);

#pragma endregion

#pragma region Functions

unsigned int __stdcall StartPacketCaptureThread(void* param)
{
    THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

    return StartPacketCapture(context->hReadyEvent, context->state);
}

void StopPacketCapture(const char* caller)
{
    s_running = false;
    if (s_handle != INVALID_HANDLE_VALUE)
    {
		WinDivertShutdown(s_handle, WINDIVERT_SHUTDOWN_RECV);
		spdlog::info("[OK][PacketCapture] {}에서 PacketCapture 종료 요청", caller);
    }
}
#pragma endregion

#pragma region Static functions

static void StopRunning(ENGINE_STATE* state)
{
    if (s_handle != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(s_handle);
		s_handle = INVALID_HANDLE_VALUE;
    }

    s_running = false;
    state->packetCaptureRunning = false;
}

static int BatchPacketCapture(HANDLE handle, unsigned char* packet, UINT* recvLen, WINDIVERT_ADDRESS* addr, std::unordered_set<UINT32>& batch)
{
    try 
    {
        if (!WinDivertRecv(handle, packet, PACKET_BUFSIZE, recvLen, addr))
            return 1;

        PWINDIVERT_IPHDR ipHdr = NULL;
        WinDivertHelperParsePacket(
            packet, *recvLen,
            &ipHdr, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL);

        if (ipHdr == NULL) return 2;

        UINT32 remoteHost = addr->Outbound ? ipHdr->DstAddr : ipHdr->SrcAddr;
        batch.insert(remoteHost);
    }
    catch (const std::exception& ex)
    {
        spdlog::error("[PacketCapture] BatchPacketCapture 예외 발생: {}", ex.what());
        return 3;
	}

    return 0;
}


static unsigned int StartPacketCapture(HANDLE hReadyEvent, ENGINE_STATE* state)
{
    std::unordered_set<UINT32> batchSet;
    DWORD64 lastFlushTime = 0;

    s_running = true;
    const char* filter =
        "outbound and ((tcp and tcp.Ack) or udp or icmp) "
        "and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) "
        "and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) "
        "and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) ";

    // 만약 filter 문법 디버깅 시 아래 코드로 필터 컴파일 에러 확인 가능
    //const char* errorStr = NULL;
    //UINT errorPos = 0;
    //if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, NULL, 0, &errorStr, &errorPos))
    //{
    //    spdlog::error("[PacketCapture] Filter error at position {}: {}", errorPos, errorStr ? errorStr : "unknown");
    //}

    s_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    if (s_handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        spdlog::error("[PacketCapture] WinDivertOpen: error {}", err);
        if (err == ERROR_ACCESS_DENIED)
            spdlog::error("[PacketCapture] 관리자 권한으로 실행하세요.");
        else if (err == 2)
            spdlog::error("[PacketCapture] WinDivert.dll / WinDivert64.sys 파일을 찾을 수 없습니다.");
        else if (err == 577)
            spdlog::error("[PacketCapture] 드라이버 서명 검증 실패. 테스트 서명 모드를 확인하세요.");
        state->packetCaptureRunning = false;
        SetEvent(hReadyEvent);
        return 1;
    }

    auto packet = std::make_unique<unsigned char[]>(PACKET_BUFSIZE);

    // Main 에게 Thread 가 준비되었음을 알림
	state->packetCaptureRunning = true;
    SetEvent(hReadyEvent);

    spdlog::info("[PacketCapture] 패킷 캡처 시작");

    WINDIVERT_ADDRESS addr;
    UINT recvLen = 0;
    lastFlushTime = GetTickCount64();

    while (s_running)
    {
        // 엔진 대기 상태 처리
        if (!WaitForEngineWaiting(state, "PacketCapture"))
        {
            spdlog::warn("[PacketCapture] 엔진이 Waiting 상태에서 중지되었습니다. 패킷 캡처를 중단합니다.");
            break;
        }

		// 패킷 수신 및 엔진 오류 상태 처리
		int batchResult = BatchPacketCapture(s_handle, packet.get(), &recvLen, &addr, batchSet);
        if (batchResult == 1) {
            if (!s_running) break;
            spdlog::error("[PacketCapture] WinDivertRecv: error {}", GetLastError());
			break;
        } else if (batchResult == 2) {
            continue;
        } else if (batchResult == 3) {
            spdlog::error("[PacketCapture] BatchPacketCapture 예외 발생, 엔진을 종료합니다.");
            break;
		} else if (batchResult != 0) {
            spdlog::error("[PacketCapture] 알 수 없는 오류 발생");
            break;
        }

		// 일정 시간마다 배치 큐에 추가
		DWORD64 now = GetTickCount64();
        if (now - lastFlushTime > 1000 && !batchSet.empty())
        {
            s_sampleQueue.Push(std::move(batchSet));
            batchSet.clear();
            lastFlushTime = now;
		}
    }

	// 종료 시 남은 배치가 있으면 큐에 추가
    if (!batchSet.empty())  
    {
        s_sampleQueue.Push(std::move(batchSet));
        batchSet.clear();
	}

	// 패킷 캡처 종료
	StopRunning(state);
    return 0;
}

#pragma endregion
