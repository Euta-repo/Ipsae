#include "pch.h"
#include "Inspector.h"
#include "DbInsert.h"
#include "PacketCapture.h"

#include <WinSock2.h> // Windows Sockets API
#include <ws2tcpip.h>
#include <iphlpapi.h> // IP Helper API
#include <winternl.h> // NtQueryInformationProcess 함수 사용을 위한 헤더

#pragma comment(lib, "Iphlpapi.lib") // IP Helper API 라이브러리 링크
#pragma comment(lib, "ws2_32.lib") // Windows Sockets API 라이브러리 링크

//TODO: 엔진 중지 시 Queue에 남은 데이터 모두 처리 후 Thread 종료하도록 수정 필요 (현재는 Thread가 먼저 종료되어 데이터 유실 가능성 존재)
//TODO: STATUS_WAITING 상태에서 대기하도록 수정 필요 (현재는 대기 상태를 고려하지 않고 바로 처리)

#pragma region Variables

static ThreadSafeQueue<std::unordered_set<UINT32>> inspectQueue;
static std::unordered_set<UINT32> threatHosts;
std::unordered_set<UINT32> hosts;

#pragma endregion

#pragma region Forward declaration

unsigned int StartInspector(HANDLE hReadyEvent, ENGINE_STATE* state);
void getTcpPID(const MIB_TCPTABLE_OWNER_PID* curTable, const UINT32 ip, UINT32* curPID);
void getUdpPID(const MIB_UDPTABLE_OWNER_PID* curTable, const UINT32 ip, UINT32* curPID);
void getProcessTree(DB_INSERT_DATA* dbData, const UINT32 targetPID);
UINT32 getLocalIp();

#pragma endregion

#pragma region Functions

void EnqueueInspect(std::unordered_set<UINT32>&& data)
{
	inspectQueue.Push(std::move(data));
}

unsigned int __stdcall StartInspectorThread(void* param)
{
	THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

	return StartInspector(context->hReadyEvent, context->state);
}

#pragma endregion

#pragma region Static functions

static unsigned int StartInspector(HANDLE hReadyEvent, ENGINE_STATE* state)
{
	DB_INSERT_BATCH batch; // DB에 삽입할 데이터 배치 저장용
	// 추후 사용할 변수 선언
	char ipStr[16]; // IPv4 주소 문자열 저장용 버퍼

	ULONG tableSize = 0; // GetExtendedTcpTable 함수에서 필요한 버퍼 크기 저장용 변수

	UINT32 targetPID = 0; // PID 저장용

	GetThreatHostsFromDb(&threatHosts); // DB에서 위협 호스트 목록 가져오기

	// Main 에게 Thread 가 준비되었음을 알림
	state->inspectorRunning = true;
	SetEvent(hReadyEvent);
	 
	// While 문 진입 - Queue 에서 데이터 가져오기
	while (inspectQueue.WaitAndPop(hosts)) {

		// While 문 진입 - set에서 데이터 1개씩 가져오기
		for (UINT32 ip : hosts) {

			DB_INSERT_DATA dbData; // DB에 삽입할 데이터 저장용 구조체

			// IP 주소 문자열 초기화
			memset(ipStr, 0, sizeof(ipStr));

			// IP 주소를 문자열로 변환
			IpToStr(ip, ipStr, sizeof(ipStr));

			// IP 저장 - DB_INSERT_DATA 구조체에 IP 저장
			dbData.network.remoteIp = ntohl(ip);
			dbData.network.isThreat = 0; // 초기값 설정 
			dbData.network.length = getPacketLength();
			dbData.network.protocol = getProtocol();
			dbData.network.timestamp = getPacketTimestamp();

			if (getDirection()) {
				dbData.network.direction = 1; // OUT
				dbData.network.localPort = getDstPort();
				dbData.network.remotePort = getSrcPort();
			}
			else {
				dbData.network.direction = 0; // IN
				dbData.network.localPort = getSrcPort();
				dbData.network.remotePort = getDstPort();
			}

			// 가져온 데이터와 DB에서 가져온 위협 호스트 목록과 비교
			// if문 실행 - 위협 호스트인 경우
			if (threatHosts.find(ip) != threatHosts.end()) {

				// 현재 프로세스 정보 탐색
				// 프로토콜에 따라 탐색 방법 분기

				dbData.network.isThreat = 1; 

				if (dbData.network.protocol == 6) {
					
					MIB_TCPTABLE_OWNER_PID* tcpTable = NULL; // TCP 연결 정보 저장용 구조체 포인터
					tableSize = 0;

					// TCP 연결 정보 가져오기 - table size를 먼저 가져오기
					DWORD errCheck = GetExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
					if (errCheck != ERROR_INSUFFICIENT_BUFFER)
					{
						spdlog::error("[Inspector] GetExtendedTcpTable size query failed: {}", errCheck);
						continue;
					}

					// tcpTable 메모리 할당
					tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tableSize);
					if (!tcpTable)
					{
						spdlog::error("[Inspector] malloc failed: {} bytes", tableSize);
						continue;
					}

					// TCP 연결 정보 가져오기 - tcpTable에 저장
					errCheck = GetExtendedTcpTable(tcpTable, &tableSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
					if (errCheck != NO_ERROR)
					{
						spdlog::error("[Inspector] GetExtendedTcpTable data query failed: {}", errCheck);
						free(tcpTable);
						tcpTable = NULL;
						continue;
					}

					// PID 찾기
					getTcpPID(tcpTable, ip, &targetPID);

					// 예외 : PID가 0인 경우 (일치하는 IP가 없는 경우)
					if (targetPID == 0) {
						spdlog::warn("[Inspector] 일치하는 IP가 없습니다: {}", ipStr);
						free(tcpTable);
						continue;
					}

					// Process 정보 탐색 - PID로 프로세스 트리 탐색 후 DB_INSERT_DATA 구조체에 저장
					getProcessTree(&dbData, targetPID);

					// 메모리 해제
					free(tcpTable);
					tcpTable = NULL;

				}
				else if (dbData.network.protocol == 17) {

					MIB_UDPTABLE_OWNER_PID* udpTable = NULL; // UDP 연결 정보 저장용 구조체 포인터
					tableSize = 0;

					// TCP 연결 정보 가져오기 - table size를 먼저 가져오기
					DWORD errCheck = GetExtendedUdpTable(NULL, &tableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
					if (errCheck != ERROR_INSUFFICIENT_BUFFER)
					{
						spdlog::error("[Inspector] GetExtendedUdpTable size query failed: {}", errCheck);
						continue;
					}

					// udpTable 메모리 할당
					udpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(tableSize);
					if (!udpTable)
					{
						spdlog::error("[Inspector] malloc failed: {} bytes", tableSize);
						continue;
					}

					// TCP 연결 정보 가져오기 - udpTable에 저장
					errCheck = GetExtendedUdpTable(udpTable, &tableSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
					if (errCheck != NO_ERROR)
					{
						spdlog::error("[Inspector] GetExtendedUdpTable data query failed: {}", errCheck);
						free(udpTable);
						udpTable = NULL;
						continue;
					}

					// PID 찾기
					getUdpPID(udpTable, getSrcPort(), &targetPID);

					// 예외 : PID가 0인 경우 (일치하는 IP가 없는 경우)
					if (targetPID == 0) {
						spdlog::warn("[Inspector] 일치하는 IP가 없습니다: {}", ipStr);
						free(udpTable);
						continue;
					}

					// Process 정보 탐색 - PID로 프로세스 트리 탐색 후 DB_INSERT_DATA 구조체에 저장
					getProcessTree(&dbData, targetPID);

					// 메모리 해제
					free(udpTable);
					udpTable = NULL;
				}
				
			}

			// DB_INSERT_BATCH 구조체에 데이터 채우기	
			batch.push_back(dbData);
		}

		// DB Insert Queue에 데이터 전달
		EnqueueDbInsert(batch);

		// Batch 초기화
		batch.clear();

		// 종료 코드 추가했당 - 20260316 Kiyeon
		if (CheckEngineStopping(state) && state->packetCaptureRunning == false) 
		{
			spdlog::info("[Inspector] PacketCapture 종료가 확인되어 Inspector 중지합니다.");
			break;
		}
	}


	// 여기도 - 20260316 Kiyeon
	spdlog::info("[Inspector] Inspector 스레드 정상 종료");
	state->inspectorRunning = false;

	return 0;
}

// Table에서 Loop로 해당 ip와 일치하는 PID 가져오는 함수
void getTcpPID(const MIB_TCPTABLE_OWNER_PID* curTable, const UINT32 ip, UINT32* curPID) {
	UINT32 check;
	for (UINT32 i = 0; i < curTable->dwNumEntries; i++) {
		check = ntohl(curTable->table[i].dwRemoteAddr); // ntohl 함수를 사용하여 네트워크 바이트 순서에서 호스트 바이트 순서로 변환
		if (check == ip) { 
			*curPID = curTable->table[i].dwOwningPid;
			return;
		}
	}
	*curPID = 0; // 일치하는 IP가 없는 경우 PID를 0으로 설정
}

void getUdpPID(const MIB_UDPTABLE_OWNER_PID* curTable, const UINT32 srcPort, UINT32* curPID) {
	UINT32 check;
	for (UINT32 i = 0; i < curTable->dwNumEntries; i++) {
		check = curTable->table[i].dwLocalPort; // ntohl 함수를 사용하여 네트워크 바이트 순서에서 호스트 바이트 순서로 변환
		if (check == srcPort) {
			*curPID = curTable->table[i].dwOwningPid;
			return;
		}
	}
	*curPID = 0; // 일치하는 IP가 없는 경우 PID를 0으로 설정
}

void getProcessTree(DB_INSERT_DATA* dbData, const UINT32 targetPID) {

	//-----------------------------------------------------------
	HANDLE hProcess = NULL; // 프로세스 핸들 저장
	PROCESS_BASIC_INFORMATION pbi; // 프로세스 정보 저장용 구조체
	char procName[MAX_PATH]; // 프로세스 이름 저장용 버퍼
	DWORD procNameSize = MAX_PATH; // 프로세스 이름 버퍼 크기
	PROCESS_LOG procLog; // 프로세스 로그 저장용
	//-----------------------------------------------------------

	// PID로 프로세스 접근 통로 open 후 프로세스 핸들 저장
	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPID);

	// 예외: 프로세스 핸들이 NULL인 경우 (프로세스 접근 실패)
	if (hProcess == NULL) {
		spdlog::error("[Inspector] OpenProcess 실패: PID {}, Error : {}", targetPID, (unsigned int)GetLastError());
		return;
	}

	// 프로세스 정보 가져오기 
	QueryFullProcessImageNameA(hProcess, 0, procName, &procNameSize); // 프로세스 경로 가져오기
	procLog.procPath = std::string(procName); // 프로세스 경로 저장

	for (int i = strlen(procName) - 1; i >= 0; i--) { // 프로세스 이름 추출
		if (procName[i] == '\\') {
			procLog.procName = std::string(&procName[i + 1]);
			break;
		}
	}

	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL); // 프로세스 정보 가져오기

	procLog.pid = (DWORD)pbi.UniqueProcessId; // ULONG_PTR to DWORD
	procLog.ppid = (DWORD)pbi.InheritedFromUniqueProcessId;

	FILETIME createTime, exitTime, kernelTime, userTime; // 프로세스 생성 시간 저장용 구조체
	GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime); // 프로세스 생성 시간 가져오기

	SYSTEMTIME st;
	FileTimeToLocalFileTime(&createTime, &createTime);
	FileTimeToSystemTime(&createTime, &st);

	ULARGE_INTEGER uli;
	uli.LowPart = createTime.dwLowDateTime;
	uli.HighPart = createTime.dwHighDateTime;

	procLog.procCreate = (UINT32)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
	procLog.timestamp = (UINT32)time(NULL); // 현재 시간 저장

	dbData->processes.push_back(procLog); // 프로세스 로그 저장

	if (procLog.ppid != 0 && procLog.ppid != procLog.pid && procLog.ppid > 4) { // ppid 가 0이 아니고, 자기 자신이 아니고, 시스템 프로세스(4)보다 큰 경우에만 부모 프로세스 탐색
		getProcessTree(dbData, procLog.ppid); // PPID가 0이 아니면 재귀적으로 호출하여 부모 프로세스 트리 탐색
	}

	CloseHandle(hProcess); // 프로세스 핸들 닫기
}

UINT32 getLocalIP() {
	char hostname[256];
	gethostname(hostname, sizeof(hostname));
	struct hostent* host = gethostbyname(hostname);
	if (host == NULL) {
		spdlog::error("[Inspector] gethostbyname failed: {}", WSAGetLastError());
		return 0;
	}
	return *(UINT32*)host->h_addr_list[0];
}

#pragma endregion

