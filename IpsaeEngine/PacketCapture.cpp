#include "pch.h"
#include "PacketCapture.h"
#include <windivert.h>

#pragma comment(lib, "WinDivert.lib")

#pragma region Variables

#define PACKET_BUFSIZE  0xFFFF // 최대 패킷 크기 (65535 바이트)

static std::atomic<bool> s_running{ false };

#pragma endregion

#pragma region Forward declaration

static void FormatIPv4(UINT32 addr, char* buf, size_t bufLen);
static const char* ProtocolName(UINT8 proto);
static unsigned int StartPacketCapture(HANDLE hReadyEvent);

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

static unsigned int StartPacketCapture(HANDLE hReadyEvent)
{
    s_running = true;

    HANDLE handle = WinDivertOpen("ip", WINDIVERT_LAYER_NETWORK, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        wprintf(L"[FAIL][PacketCapture] WinDivertOpen: error %lu\n", err);
        if (err == ERROR_ACCESS_DENIED)
            wprintf(L"       -> 관리자 권한으로 실행하세요.\n");
        else if (err == 2)
            wprintf(L"       -> WinDivert.dll / WinDivert64.sys 파일을 찾을 수 없습니다.\n");
        else if (err == 577)
            wprintf(L"       -> 드라이버 서명 검증 실패. 테스트 서명 모드를 확인하세요.\n");
        SetEvent(hReadyEvent);
        return 1;
    }

	// Main 에게 Thread 가 준비되었음을 알림
    SetEvent(hReadyEvent);

    wprintf(L"[OK][PacketCapture] 패킷 캡처 시작\n");
    wprintf(L"%-5s %-5s %-21s    %-21s %s\n",
        L"방향", L"프로토콜", L"출발지", L"목적지", L"크기");
    wprintf(L"───────────────────────────────────────────────────────────────────\n");

    unsigned char* packet = (unsigned char*)malloc(PACKET_BUFSIZE);
    if (!packet) 
    {
        wprintf(L"[FAIL][PacketCapture] 패킷 버퍼 할당 실패\n");
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

            const wchar_t* dir = addr.Outbound ? L"OUT" : L"IN ";

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
                wprintf(L"[%s] %hs %hs:%-5u -> %hs:%-5u  len=%u\n",
                    dir, ProtocolName(protocol),
                    srcStr, srcPort, dstStr, dstPort, totalLen);
            }
            else
            {
                wprintf(L"[%s] %hs %-21hs -> %-21hs  len=%u\n",
                    dir, ProtocolName(protocol),
                    srcStr, dstStr, totalLen);
            }
        }
    }
    catch (...)
    {
        wprintf(L"[ERROR][PacketCapture] 패킷 수신 중 예외 발생\n");
    }
    
    free(packet);

    if (WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH))
        wprintf(L"[OK][PacketCapture] WinDivert Shutdown 성공\n");
    else
        wprintf(L"[FAIL][PacketCapture] WinDivertShutdown: error %lu\n", GetLastError());

    if (WinDivertClose(handle))
        wprintf(L"[OK][PacketCapture] WinDivert 핸들 닫기 성공\n");
    else
        wprintf(L"[FAIL][PacketCapture] WinDivertClose: error %lu\n", GetLastError());

    return 0;
}

#pragma endregion