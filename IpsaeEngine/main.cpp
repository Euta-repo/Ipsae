#include <windows.h>
#include <windivert.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "WinDivert.lib")

// 패킷 수신 버퍼 크기 (최대 MTU + 여유)
#define PACKET_BUFSIZE  0xFFFF

static volatile BOOL g_running = TRUE;

static BOOL WINAPI CtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT)
    {
        g_running = FALSE;
        return TRUE;
    }
    return FALSE;
}

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

int wmain()
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    wprintf(L"=== IpsaeEngine 패킷 캡처 (WinDivert) ===\n");
    wprintf(L"Ctrl+C 로 종료\n\n");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

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
        return 1;
    }

    wprintf(L"[OK] 패킷 캡처 시작\n");
    wprintf(L"%-5s %-5s %-21s    %-21s %s\n",
        L"방향", L"프로토콜", L"출발지", L"목적지", L"크기");
    wprintf(L"───────────────────────────────────────────────────────────────────\n");

    unsigned char packet[PACKET_BUFSIZE];
    WINDIVERT_ADDRESS addr;
    UINT recvLen = 0;

    while (g_running)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &recvLen, &addr))
        {
            if (!g_running) break;
            continue;
        }

        PWINDIVERT_IPHDR  ipHdr  = NULL;  // IPv4 헤더
        PWINDIVERT_TCPHDR tcpHdr = NULL;  // TCP 헤더
        PWINDIVERT_UDPHDR udpHdr = NULL;  // UDP 헤더
        UINT8 protocol = 0;               // 프로토콜 번호 (6=TCP, 17=UDP, 1=ICMP)

        WinDivertHelperParsePacket(
            packet, recvLen,
            &ipHdr,     // [출력] IPv4 헤더 포인터
            NULL,       // IPv6 헤더 (불필요 - IPv4만 캡처)
            &protocol,  // [출력] 상위 프로토콜 번호
            NULL,       // ICMP 헤더 (불필요)
            NULL,       // ICMPv6 헤더 (불필요)
            &tcpHdr,    // [출력] TCP 헤더 포인터 (TCP 패킷이면 유효)
            &udpHdr,    // [출력] UDP 헤더 포인터 (UDP 패킷이면 유효)
            NULL,       // 페이로드 데이터 포인터 (불필요)
            NULL,       // 페이로드 길이 (불필요)
            NULL,       // 다음 헤더 포인터 (불필요)
            NULL        // 다음 헤더 길이 (불필요)
        );

        if (ipHdr == NULL) continue;

        const wchar_t* dir = addr.Outbound ? L"OUT" : L"IN ";

        // 출발지/목적지 IP 주소를 문자열로 변환
        char srcStr[32], dstStr[32];
        FormatIPv4(ipHdr->SrcAddr, srcStr, sizeof(srcStr));
        FormatIPv4(ipHdr->DstAddr, dstStr, sizeof(dstStr));

        // 포트 번호 추출 (TCP/UDP인 경우에만)
        // WinDivert의 포트는 네트워크 바이트 오더(빅엔디안)이므로
        // WinDivertHelperNtohs()로 호스트 바이트 오더로 변환
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

        // 전체 패킷 길이 (네트워크 바이트 오더 -> 호스트)
        UINT16 totalLen = WinDivertHelperNtohs(ipHdr->Length);

        // 콘솔 출력
        if (srcPort != 0)
        {
            // TCP/UDP: IP:포트 형식
            wprintf(L"[%s] %hs %hs:%-5u -> %hs:%-5u  len=%u\n",
                dir,
                ProtocolName(protocol),
                srcStr, srcPort,
                dstStr, dstPort,
                totalLen);
        }
        else
        {
            // ICMP 등: 포트 없이 IP만 표시
            wprintf(L"[%s] %hs %-21hs -> %-21hs  len=%u\n",
                dir,
                ProtocolName(protocol),
                srcStr,
                dstStr,
                totalLen);
        }
    } 

    if (WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH)) {
        wprintf(L"[OK] WinDivert Shutdown 성공\n");
    } else {
        DWORD err = GetLastError();
        wprintf(L"[FAIL] WinDivertShutdown: error %lu\n", err);
    }
    if (WinDivertClose(handle)) {
        wprintf(L"[OK] WinDivert 핸들 닫기 성공\n");
    } else {
        DWORD err = GetLastError();
        wprintf(L"[FAIL] WinDivertClose: error %lu\n", err);
    }
    wprintf(L"\n[OK] 패킷 캡처 종료\n");

    return 0;
}
