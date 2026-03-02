#include "PacketCapture.h"
#include <windivert.h>
#include <stdio.h>

#pragma comment(lib, "WinDivert.lib")

#define PACKET_BUFSIZE  0xFFFF // 최대 패킷 크기 (65535 바이트)

static volatile BOOL g_running = FALSE;

/// <summary>
/// 32비트 정수를 IPv4 주소 문자열로 포맷합니다.
/// </summary>
/// <param name="addr">포맷할 IPv4 주소(32비트 정수).</param>
/// <param name="buf">포맷된 IPv4 주소 문자열을 저장할 버퍼.</param>
/// <param name="bufLen">버퍼의 크기(바이트).</param>
static void FormatIPv4(UINT32 addr, char* buf, size_t bufLen)
{
    UINT8* b = (UINT8*)&addr;
    sprintf_s(buf, bufLen, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/// <summary>
/// 프로토콜 번호에 해당하는 프로토콜 이름을 반환합니다.
/// </summary>
/// <param name="proto">프로토콜 번호 (예: 1=ICMP, 6=TCP, 17=UDP).</param>
/// <returns>프로토콜 이름 문자열. 알 수 없는 프로토콜의 경우 "??? "를 반환합니다.</returns>
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

/// <summary>
/// 패킷 캡처를 시작하는 스레드 진입점 함수입니다.
/// </summary>
/// <param name="param">THREAD_CONTEXT 구조체에 대한 포인터로, 스레드 컨텍스트 정보를 포함합니다.</param>
/// <returns>패킷 캡처 작업의 결과 코드입니다.</returns>
unsigned int __stdcall StartPacketCaptureThread(void* param)
{
    THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

    return StartPacketCapture(context->hReadyEvent);
}

/// <summary>
/// 패킷 캡처를 중지합니다.
/// </summary>
void StopPacketCapture()
{
    g_running = FALSE;
}

/// <summary>
/// WinDivert를 사용하여 네트워크 패킷 캡처를 시작하고 패킷 정보를 콘솔에 출력합니다.
/// </summary>
/// <param name="hReadyEvent">패킷 캡처 준비가 완료되었을 때 신호를 보낼 이벤트 핸들입니다.</param>
/// <returns>패킷 캡처가 성공적으로 시작되고 완료되면 true를 반환하고, 실패하면 false를 반환합니다.</returns>
bool StartPacketCapture(HANDLE hReadyEvent)
{
    g_running = TRUE;

    HANDLE handle = WinDivertOpen("ip", WINDIVERT_LAYER_NETWORK, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        wprintf(L"[FAIL] WinDivertOpen: error %lu\n", err);
        if (err == ERROR_ACCESS_DENIED)
            wprintf(L"       -> 관리자 권한으로 실행하세요.\n");
        else if (err == 2)
            wprintf(L"       -> WinDivert.dll / WinDivert64.sys 파일을 찾을 수 없습니다.\n");
        else if (err == 577)
            wprintf(L"       -> 드라이버 서명 검증 실패. 테스트 서명 모드를 확인하세요.\n");
        return false;
    }

	// Main 에게 Thread 가 준비되었음을 알림
    SetEvent(hReadyEvent);

    wprintf(L"[OK] 패킷 캡처 시작\n");
    wprintf(L"%-5s %-5s %-21s    %-21s %s\n",
        L"방향", L"프로토콜", L"출발지", L"목적지", L"크기");
    wprintf(L"───────────────────────────────────────────────────────────────────\n");

    unsigned char* packet = (unsigned char*)malloc(PACKET_BUFSIZE);
    if (!packet) 
    {
        wprintf(L"[FAIL] 패킷 버퍼 할당 실패\n");
        WinDivertClose(handle);
		return false;
    }

    WINDIVERT_ADDRESS addr;
    UINT recvLen = 0;

    try
    {
        while (g_running)
        {
            if (!WinDivertRecv(handle, packet, PACKET_BUFSIZE, &recvLen, &addr))
            {
                if (!g_running) break;
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
        wprintf(L"[ERROR] 패킷 수신 중 예외 발생\n");
    }
    
    free(packet);

    if (WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH))
        wprintf(L"[OK] WinDivert Shutdown 성공\n");
    else
        wprintf(L"[FAIL] WinDivertShutdown: error %lu\n", GetLastError());

    if (WinDivertClose(handle))
        wprintf(L"[OK] WinDivert 핸들 닫기 성공\n");
    else
        wprintf(L"[FAIL] WinDivertClose: error %lu\n", GetLastError());

    return true;
}
