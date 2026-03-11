#include "pch.h"
#include "Inspector.h"
#include "DbInsert.h"
#include "PacketCapture.h"

#include <WinSock2.h> // Windows Sockets API
#include <ws2tcpip.h>
#include <iphlpapi.h> // IP Helper API
#include <winternl.h> // NtQueryInformationProcess 함수 사용을 위한 헤더

#pragma comment(lib, "Iphlpapi.lib") // IP Helper API 라이브러리 링크

#pragma region Variables

static ThreadSafeQueue<std::unordered_set<UINT32>> inspectQueue;
static std::unordered_set<UINT32>& threatHosts;

std::unordered_set<UINT32> hosts;

#pragma endregion

#pragma region Forward declaration

void getPID(const MIB_TCPTABLE_OWNER_PID* curTable, const UINT32 ip, UINT32* curPID);
void getProcessTree(DB_INSERT_DATA* dbData, const UINT32 targetPID);

#pragma endregion

#pragma region Functions

void EnqueueInspect(const std::unordered_set<UINT32>& data)
{
	// 이 함수는 PacketCapture 스레드에서 캡처된 네트워크 로그의 IP 주소 집합을 Inspector 스레드로 전달하는 역할을 합니다.
	inspectQueue.Push(data);
}

unsigned int __stdcall StartInspectorThread(void* param)
{
	THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;
	// 이 함수는 Inspector 스레드의 진입점입니다.
	// inspectQueue에서 데이터를 대기하고 처리하는 로직을 구현해야 합니다.
	// 예시:
	/*
	std::unordered_set<UINT32> data;
	while (inspectQueue.WaitAndPop(data))
	{
		// 데이터 처리 로직
		// 예: DB에서 위협 호스트 목록과 비교하여 로그 생성
	}
	*/
	return StartInspector(context->hReadyEvent, context->state);
}

#pragma endregion

#pragma region Static functions

/*
*	GetExtendedTcpTable() - MIB_TCPTABLE_OWNER_PID, bufsize; dwOwningPid
*	OpenProcess()
*	QueryFullProcessImageName() - ProcessImageFileName for NtQueryInformationProcess()
*	NtQueryInformationProcess() - InheritedFromUniqueProcessId
*/

static unsigned int StartInspector(HANDLE hReadyEvent, ENGINE_STATE* state)
{
	DB_INSERT_BATCH batch; // DB에 삽입할 데이터 배치 저장용
	// 추후 사용할 변수 선언
	char ipStr[16]; // IPv4 주소 문자열 저장용 버퍼

	MIB_TCPTABLE_OWNER_PID* tcpTable = NULL; // TCP 연결 정보 저장용 구조체 포인터
	ULONG tableSize = 0; // GetExtendedTcpTable 함수에서 필요한 버퍼 크기 저장용 변수

	UINT32 targetPID = 0; // PID 저장용

	DB_INSERT_DATA dbData; // DB에 삽입할 데이터 저장용 구조체
	 
	// Main 에게 Thread 가 준비되었음을 알림
	state->inspectorRunning = true;
	SetEvent(hReadyEvent);
	 
	// While 문 진입 - Queue 에서 데이터 가져오기
	while (inspectQueue.WaitAndPop(hosts)) {
		
		// While 문 진입 - set에서 데이터 1개씩 가져오기
		for (UINT32 ip : hosts) {

			// IP 주소 문자열 초기화
			memset(ipStr, 0, sizeof(ipStr));

			// IP 주소를 문자열로 변환
			IpToStr(ip, ipStr, sizeof(ipStr));

			// IP 저장 - DB_INSERT_DATA 구조체에 IP 저장
			dbData.network.remoteIp = ip;

			// 가져온 데이터와 DB에서 가져온 위협 호스트 목록과 비교
			// if문 실행 - 위협 호스트인 경우
			if (threatHosts.find(ip) != threatHosts.end()) {

				// 현재 프로세스 정보 탐색
				// TCP 연결 정보 가져오기 - table size를 먼저 가져오기
				GetExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

				// tcpTable 메모리 할당
				tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tableSize);
				
				// TCP 연결 정보 가져오기 - tcpTable에 저장
				GetExtendedTcpTable(tcpTable, &tableSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

				// PID 찾기
				getPID(tcpTable, ip, &targetPID);

				// 예외 : PID가 0인 경우 (일치하는 IP가 없는 경우)
				if (targetPID == 0) {
					spdlog::warn("[Inspector] 일치하는 IP가 없습니다: {}", ipStr);
					continue;
				}

				// Process 정보 탐색 - PID로 프로세스 트리 탐색 후 DB_INSERT_DATA 구조체에 저장
				getProcessTree(&dbData, targetPID);
	
				// Network 정보는 IP만 채우기
				// Process 정보는 최대한 많이 채우되, PID/PPID 위주로
				/*struct DB_INSERT_DATA
				{
					NETWORK_LOG network;
					std::vector<PROCESS_LOG> processes;
				};*/

			}

			// DB_INSERT_BATCH 구조체에 데이터 채우기	
			batch.push_back(dbData);
		}

		// DB Insert Queue에 데이터 전달
		EnqueueDbInsert(batch);

		// Batch 초기화
		batch.clear();
	}

	return 0;
}

// Table에서 Loop로 해당 ip와 일치하는 PID 가져오는 함수
void getPID(const MIB_TCPTABLE_OWNER_PID* curTable, const UINT32 ip, UINT32* curPID) {
	for (UINT32 i = 0; i < curTable->dwNumEntries; i++) {
		if (curTable->table[i].dwRemoteAddr == ip) {
			*curPID = curTable->table[i].dwOwningPid;
			return;
		}
	}
	*curPID = 0; // 일치하는 IP가 없는 경우 PID를 0으로 설정
}

void getProcessTree(DB_INSERT_DATA* dbData, const UINT32 targetPID) {

	//-----------------------------------------------------------
	HANDLE hProcess = NULL; // 프로세스 핸들 저장
	SYSTEM_BASICPROCESS_INFORMATION pbi; // 프로세스 정보 저장용 구조체
	char procName[MAX_PATH]; // 프로세스 이름 저장용 버퍼
	ULONG pbufSize = 0; // NtQueryInformationProcess 함수에서 필요한 버퍼 크기 저장용 변수
	PROCESS_LOG procLog; // 프로세스 로그 저장용
	//-----------------------------------------------------------

	// PID로 프로세스 접근 통로 open 후 프로세스 핸들 저장
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);

	// 예외: 프로세스 핸들이 NULL인 경우 (프로세스 접근 실패)
	if (hProcess == NULL) {
		spdlog::error("[Inspector] OpenProcess 실패: PID {}", targetPID);
		return;
	}

	// 프로세스 정보 가져오기 
	QueryFullProcessImageNameA(hProcess, 0, procName, &pbufSize); // 프로세스 경로 가져오기
	procLog.procPath = std::string(procName); // 프로세스 경로 저장

	for (int i = strlen(procName) - 1; i >= 0; i--) { // 프로세스 이름 추출
		if (procName[i] == '\\') {
			procLog.procName = std::string(&procName[i + 1]);
			break;
		}
	}

	NtQueryInformationProcess(hProcess, ProcessBasicInformation, NULL, 0, &pbufSize); // 필요한 버퍼 크기 가져오기
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, pbufSize, NULL); // 프로세스 정보 가져오기

	procLog.pid = (DWORD)pbi.UniqueProcessId; // ULONG_PTR to DWORD
	procLog.ppid = (DWORD)pbi.InheritedFromUniqueProcessId;

	if (procLog.ppid != 0) {
		getProcessTree(dbData, procLog.ppid); // PPID가 0이 아니면 재귀적으로 호출하여 부모 프로세스 트리 탐색
	}

	dbData->processes.push_back(procLog); // 프로세스 로그 저장

	CloseHandle(hProcess); // 프로세스 핸들 닫기
}

/*
/// 재귀적으로 PPID 가져오는 함수 작성
void getPPID(DWORD pid, std::vector <DWORD> & ppidList) {

	PROCESS_LOG ppidLog; // PPID 로그 저장용 구조체
	ULONG pbufSize = 0; // NtQueryInformationProcess 함수에서 필요한 버퍼 크기 저장용 변수
	SYSTEM_BASICPROCESS_INFORMATION pbi; // 프로세스 정보 저장용 구조체

	auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

	NtQueryInformationProcess(hProcess, ProcessBasicInformation, NULL, 0, &pbufSize); // 필요한 버퍼 크기 가져오기
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, pbufSize, NULL); // 프로세스 정보 가져오기
	
	// 현재 프로세스의 PPID 가져오기
	ppidLog.ppid = (DWORD)pbi.InheritedFromUniqueProcessId;

	if (ppidLog.ppid == 0) {
		CloseHandle(hProcess);
		return; // PPID가 0인 경우 종료
	}

	ppidList.push_back(ppidLog.ppid);

	getPPID(ppidLog.ppid, ppidList);

	// 
	// ppidList에 추가
	// PPID가 0이 아니면 재귀적으로 호출하여 부모 프로세스 트리 탐색
}
*/

#pragma endregion

