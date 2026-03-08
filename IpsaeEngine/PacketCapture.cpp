#include "pch.h"
#include "PacketCapture.h"
#include <windivert.h>

#pragma comment(lib, "WinDivert.lib")

#pragma region Variables

#define PACKET_BUFSIZE  0xFFFF // 최대 패킷 크기 (65535 바이트)

static std::atomic<bool> s_running{ false };

static HANDLE s_handle = INVALID_HANDLE_VALUE;

#pragma endregion

#pragma region Forward declaration

static void FormatIPv4(UINT32 addr, char* buf, size_t bufLen);
static const char* ProtocolName(UINT8 proto);
//static unsigned int StartPacketCapture(HANDLE hReadyEvent);

#pragma endregion

#pragma region Functions

unsigned int __stdcall StartPacketCaptureThread(void* param)
{
    THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

    return StartPacketCapture(context->hReadyEvent);
}

void StopPacketCapture()
{
    s_running = false;

    if (s_handle != INVALID_HANDLE_VALUE)
        WinDivertShutdown(s_handle, WINDIVERT_SHUTDOWN_RECV);
}

#pragma endregion

#pragma region Static functions

static void FormatIPv4(UINT32 addr, char* buf, size_t bufLen)
{
    UINT8* b = (UINT8*)&addr;
    sprintf_s(buf, bufLen, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static const char* ProtocolName(UINT8 proto)
{
    switch (proto)
    {
        case  1: return "ICMP";
        case  6: return "TCP ";
        case 17: return "UDP ";
        default: return "??? ";
    }
}

unsigned int StartPacketCapture(HANDLE hReadyEvent)
{
    s_running = true;
    const char* filter =
        "outbound and ((tcp and tcp.Ack) or udp or icmp) "
        "and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) "
        "and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) "
        "and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) ";

    const char* errorStr = NULL;
    UINT errorPos = 0;
    if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, NULL, 0, &errorStr, &errorPos));
    {
        spdlog::error("[PacketCapture] Filter error at position {}: {}", errorPos, errorStr ? errorStr : "unknown");
    }
    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        spdlog::error("[PacketCapture] WinDivertOpen: error {}", err);
        if (err == ERROR_ACCESS_DENIED)
            spdlog::error("[PacketCapture]   -> 관리자 권한으로 실행하세요.");
        else if (err == 2)
            spdlog::error("[PacketCapture]   -> WinDivert.dll / WinDivert64.sys 파일을 찾을 수 없습니다.");
        else if (err == 577)
            spdlog::error("[PacketCapture]   -> 드라이버 서명 검증 실패. 테스트 서명 모드를 확인하세요.");
        //SetEvent(hReadyEvent);
        return 1;
    }

	// Main 에게 Thread 가 준비되었음을 알림
    //SetEvent(hReadyEvent);

    spdlog::info("[PacketCapture] 패킷 캡처 시작");
    spdlog::info("{:<5} {:<8} {:<21}    {:<21} {}", "방향", "프로토콜", "출발지", "목적지", "크기");
    spdlog::info("───────────────────────────────────────────────────────────────────");

    unsigned char* packet = (unsigned char*)malloc(PACKET_BUFSIZE);
    if (!packet)
    {
        spdlog::error("[PacketCapture] 패킷 버퍼 할당 실패");
        WinDivertClose(handle);
		return 1;
    }

    WINDIVERT_ADDRESS addr;
    UINT recvLen = 0;

    try
    {
        while (s_running)
        {
            if (!WinDivertRecv(handle, packet, PACKET_BUFSIZE, &recvLen, &addr))
            {
                if (!s_running) break;
                continue;
            }

            PWINDIVERT_IPHDR  ipHdr = NULL;
            PWINDIVERT_TCPHDR tcpHdr = NULL;
            PWINDIVERT_UDPHDR udpHdr = NULL;
            UINT8 protocol = 0;

            WinDivertHelperParsePacket(
                packet, recvLen,
                &ipHdr, NULL, &protocol, NULL, NULL,
                &tcpHdr, &udpHdr, NULL, NULL, NULL, NULL);

            if (ipHdr == NULL) continue;

            const char* dir = addr.Outbound ? "OUT" : "IN ";

            char srcStr[32], dstStr[32];
            FormatIPv4(ipHdr->SrcAddr, srcStr, sizeof(srcStr));
            FormatIPv4(ipHdr->DstAddr, dstStr, sizeof(dstStr));

            UINT16 srcPort = 0, dstPort = 0;
            if (tcpHdr != NULL)
            {
                srcPort = WinDivertHelperNtohs(tcpHdr->SrcPort);
                dstPort = WinDivertHelperNtohs(tcpHdr->DstPort);
            }
            else if (udpHdr != NULL)
            {
                srcPort = WinDivertHelperNtohs(udpHdr->SrcPort);
                dstPort = WinDivertHelperNtohs(udpHdr->DstPort);
            }

            UINT16 totalLen = WinDivertHelperNtohs(ipHdr->Length);

            if (srcPort != 0)
            {
                spdlog::info("[{}] {} {}:{} -> {}:{}  len={}",
                    dir, ProtocolName(protocol),
                    srcStr, srcPort, dstStr, dstPort, totalLen);
            }
            else
            {
                spdlog::info("[{}] {} {} -> {}  len={}",
                    dir, ProtocolName(protocol),
                    srcStr, dstStr, totalLen);
            }
        }
    }
    catch (const std::exception& ex)
    {
        spdlog::error("[PacketCapture] 패킷 수신 중 예외 발생: {}", ex.what());
    }

    free(packet);

    if (WinDivertClose(handle))
        spdlog::info("[PacketCapture] WinDivert 핸들 닫기 성공");
    else
        spdlog::error("[PacketCapture] WinDivertClose: error {}", GetLastError());

    return 0;
}

#pragma endregion
