#include "DbInsert.h"
#include "pch.h"
#include "PacketCapture.h"

#pragma region Variables

static ThreadSafeQueue<std::unordered_set<UINT32>> inspectQueue;
static std::unordered_set<UINT32>& threatHosts;

std::unordered_set<UINT32> hosts;

#pragma endregion

#pragma region Forward declaration

void getPPID(DWORD pid, std::vector<DWORD>& ppidList);

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
	return 0;
}

#pragma endregion

#pragma region Static functions

/*
*	GetExtendedTcpTable() - MIB_TCPTABLE_OWNER_PID, bufsize
*	OpenProcess()
*	QueryFullProcessImageName() - ProcessImageFileName for NtQueryInformationProcess()
*	NtQueryInformationProcess() - InheritedFromUniqueProcessId
*/

static unsigned int StartInspector(HANDLE hReadyEvent, ENGINE_STATE* state)
{
	// 추후 사용할 변수 선언
	
	 
	// Main 에게 Thread 가 준비되었음을 알림
	state->inspectorRunning = true;
	SetEvent(hReadyEvent);
	 
	// While 문 진입 - Queue 에서 데이터 가져오기
	while (inspectQueue.WaitAndPop(hosts)) {
		
		// While 문 진입 - set에서 데이터 1개씩 가져오기
		for (UINT32 ip : hosts) {

			char ipStr[16];

			// IP 주소를 문자열로 변환
			FormatIPv4(ip, ipStr, sizeof(ipStr));

			// 가져온 데이터와 DB에서 가져온 위협 호스트 목록과 비교
			// if문 실행 - 위협 호스트인 경우
			if (threatHosts.find(ip) != threatHosts.end()) {
				// 현재 프로세스 정보 탐색


				// 부모 프로세스 트리 탐색 - 함수로 분리해서 작성 및 호출

				// Network 정보는 IP만 채우기
				// Process 정보는 최대한 많이 채우되, PID/PPID 위주로
				/*struct DB_INSERT_DATA
				{
					NETWORK_LOG network;
					std::vector<PROCESS_LOG> processes;
				};*/

				// DB_INSERT_BATCH 구조체에 데이터 채우기	

			// DB Insert Queue에 데이터 전달
			}
		}

	}

	

	return 0;
}

/// 재귀적으로 PPID 가져오는 함수 작성
void getPPID(DWORD pid, std::vector<DWORD>& ppidList) {
	// 현재 프로세스의 PPID 가져오기
	// ppidList에 추가
	// PPID가 0이 아니면 재귀적으로 호출하여 부모 프로세스 트리 탐색
}



#pragma endregion

