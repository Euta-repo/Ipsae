#include "pch.h"
#include "PacketCapture.h"
#include "Inspector.h"
#include <windivert.h>

#pragma comment(lib, "WinDivert.lib")

#pragma region Variables

#define PACKET_BUFSIZE  0xFFFF // 최대 패킷 크기 (65535 바이트)

static HANDLE s_handle = INVALID_HANDLE_VALUE;
static std::unordered_set<std::string> s_debugExcludeIps;
#define debug_exclude(ip) s_debugExcludeIps.insert(ip)

int protocolType = 0;
int direction = -1; // 0: IN, 1: OUT
UINT32 srcPort = 0;
UINT32 dstPort = 0;
UINT packetLength = 0;
UINT32 packetTimestamp = 0;

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
	// WinDivert handle 닫기
    if (s_handle != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(s_handle);
		s_handle = INVALID_HANDLE_VALUE;
    }

	// 패킷 캡처 상태 플래그 업데이트
    state->packetCaptureRunning = false;
}

static int BatchPacketCapture(HANDLE handle, unsigned char* packet, UINT* recvLen, WINDIVERT_ADDRESS* addr, std::unordered_set<UINT32>& batch)
{
    try 
    {
		// 패킷 수신
        if (!WinDivertRecv(handle, packet, PACKET_BUFSIZE, recvLen, addr))
            return 1;

		packetTimestamp = (UINT32)(addr->Timestamp / 1000); // 타임스탬프를 초 단위로 변환 (밀리초에서)

		// IP 헤더 파싱
        PWINDIVERT_IPHDR ipHdr = NULL;
        PWINDIVERT_TCPHDR tcpHdr = NULL;
        PWINDIVERT_UDPHDR udpHdr = NULL;

        WinDivertHelperParsePacket(
            packet, *recvLen,
            &ipHdr, NULL, NULL, NULL, NULL,
            &tcpHdr, &udpHdr, NULL, NULL, NULL, NULL);

		packetLength = *recvLen;

        if (ipHdr == NULL) return 2;

        if (tcpHdr != NULL) {
            protocolType = 6;
			srcPort = tcpHdr->SrcPort;
			dstPort = tcpHdr->DstPort;
        }
        else if (udpHdr != NULL) {
            protocolType = 17;
            srcPort = udpHdr->SrcPort;
			dstPort = udpHdr->DstPort;
        }
        else protocolType = 0;

        direction = addr->Outbound ? 1 : 0;

        if (direction == -1) return 4;

		// 원격 호스트 IP 주소 추출 및 배치에 추가
        UINT32 remoteHost = addr->Outbound ? ipHdr->DstAddr : ipHdr->SrcAddr;
        char ipStr[16];
        IpToStr(remoteHost, ipStr, sizeof(ipStr));
        if (s_debugExcludeIps.find(ipStr) == s_debugExcludeIps.end())
            spdlog::debug("[PacketCapture] Captured: {}", ipStr);
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

	// WinDivert 필터 - 아웃바운드 TCP, UDP, ICMP 패킷 중 사설 IP 대역이 아닌 패킷만 캡처
    const char* filter =
        "outbound and (tcp or udp or icmp) "
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

	// WinDivert handle Open
    s_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

	// WinDivertOpen 실패 시 에러 처리
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

	// 패킷 버퍼 할당
    auto packet = std::make_unique<unsigned char[]>(PACKET_BUFSIZE);

    // Main 에게 Thread 가 준비되었음을 알림
	state->packetCaptureRunning = true;
    SetEvent(hReadyEvent);

    spdlog::info("[PacketCapture] 패킷 캡처 시작");

	// 디버그 로그 제외 IP 등록
	debug_exclude("182.213.91.170");
	debug_exclude("127.0.0.1");

	// 패킷 캡처 루프
    WINDIVERT_ADDRESS addr;
    UINT recvLen = 0;
    lastFlushTime = GetTickCount64(); // 배치 타이머

    while (state->packetCaptureRunning)
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
            if (CheckEngineStopping(state))
                break; // 정상 종료 (WinDivertShutdown에 의한 종료)
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
            EnqueueInspect(std::move(batchSet));
            batchSet = {};
            lastFlushTime = now;
		}

        if (CheckEngineStopping(state))
            break;
    }

	// 종료 시 남은 배치가 있으면 큐에 추가
    if (!batchSet.empty())  
    {
        EnqueueInspect(std::move(batchSet));
	}

	// 패킷 캡처 종료
    spdlog::info("[PacketCapture] 패킷 캡처 스레드 정상 종료");
	StopRunning(state);
    return 0;
}

int getProtocol() {
    return protocolType;
}

UINT32 getSrcPort() {
    return srcPort;
}

UINT32 getDstPort() {
    return dstPort;
}

int getDirection() {
    return direction;
}

UINT getPacketLength() {
    return packetLength;
}

UINT32 getPacketTimestamp() {
    return packetTimestamp;
}

#pragma endregion
