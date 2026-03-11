#pragma once
#include "pch.h"


enum ENGINE_STATUS
{
	ENGINE_INIT,		// 초기화 단계 (다시 사용하지 않음)
	ENGINE_STARTING,	// 시작 단계
	ENGINE_RUNNING,		// 실행 중
	ENGINE_STOPPING,	// 중지 단계
	ENGINE_STOPPED,		// 중지 완료
	ENGINE_ERROR,
	ENGINE_WAITING		// 대기 단계
};

struct ENGINE_STATE
{
	// 엔진 전체 상태
	ENGINE_STATUS status{ ENGINE_INIT };

	// 각 모듈의 실행 상태 플래그
	std::atomic<bool> packetCaptureRunning{ false };
	std::atomic<bool> inspectorRunning{ false };
	std::atomic<bool> dbInsertRunning{ false };
	std::atomic<bool> ipcToolRunning{ false };
};

// =============================================================================================
// Timeout
// =============================================================================================

#define TIMEOUT_WAITING     60000   // 대기 상태 타임아웃 (ms)
#define TIMEOUT_STOPPING    10000   // 종료 대기열 처리 타임아웃 (ms)

// =============================================================================================
// Thread
// =============================================================================================

/// <summary>
/// 스레드 컨텍스트 정보를 저장하는 구조체입니다.
/// </summary>
struct THREAD_CONTEXT
{
	int ThreadId;
	HANDLE hReadyEvent;
	ENGINE_STATE* state;
};

/// <summary>
/// 스레드 함수에 대한 함수 포인터 타입입니다.
/// </summary>
typedef unsigned int(__stdcall* THREAD_FUNC)(void*);

// =============================================================================================
// Queue
// =============================================================================================

/// <summary>
/// 여러 스레드에서 안전하게 접근할 수 있는 스레드 안전 큐입니다.
/// </summary>
/// <typeparam name="T">큐에 저장될 요소의 타입입니다.</typeparam>
template<typename T>
struct ThreadSafeQueue
{
	std::queue<T> queue;
	std::mutex mutex;
	std::condition_variable cv;
	bool stopped = false;

	/// <summary>
	/// 항목을 큐에 추가합니다.
	/// </summary>
	/// <param name="item">큐에 추가할 항목입니다.</param>
	void Push(const T& item)
	{
		{
			std::lock_guard<std::mutex> lock(mutex);
			if (stopped) return;
			queue.push(item);
		}
		cv.notify_one();
	}

	/// <summary>
	/// 큐에서 요소를 제거하고 반환을 시도합니다.
	/// </summary>
	/// <param name="out">큐의 앞쪽 요소가 저장될 출력 매개변수입니다.</param>
	/// <returns>요소를 성공적으로 제거하면 true를 반환하고, 큐가 비어있으면 false를 반환합니다.</returns>
	bool TryPop(T& out)
	{
		std::lock_guard<std::mutex> lock(mutex);
		if (queue.empty())
			return false;

		out = queue.front();
		queue.pop();
		return true;
	}

	/// <summary>
	/// 큐에서 요소를 대기하고 꺼냅니다.
	/// </summary>
	/// <param name="out">큐에서 꺼낸 요소를 저장할 참조 변수.</param>
	/// <returns>요소를 성공적으로 꺼냈으면 true, 큐가 중지되고 비어있으면 false를 반환합니다.</returns>
	bool WaitAndPop(T& out)
	{
		std::unique_lock<std::mutex> lock(mutex);
		cv.wait(lock, [this] { return !queue.empty() || stopped; });

		if (stopped && queue.empty())
			return false;

		out = queue.front();
		queue.pop();
		return true;
	}

	/// <summary>
	/// 큐가 비어 있는지 확인합니다.
	/// </summary>
	/// <returns>큐가 비어 있으면 true, 그렇지 않으면 false를 반환합니다.</returns>
	bool IsEmpty()
	{
		std::lock_guard<std::mutex>	lock(mutex);
		return queue.empty();
	}

	/// <summary>
	/// 스레드 풀 또는 작업자를 중지하고 대기 중인 모든 스레드에 알립니다.
	/// </summary>
	void Stop()
	{
		{
			std::lock_guard<std::mutex> lock(mutex);
			stopped = true;
		}
		cv.notify_all();
	}

	/// <summary>
	///	Queue의 현재 크기를 반환합니다.
	/// </summary>
	/// <returns>큐의 현재 크기입니다.</returns>
	int Size()
	{
		std::lock_guard<std::mutex> lock(mutex);
		return static_cast<int>(queue.size());
	}
};

// =============================================================================================
// Common functions
// =============================================================================================

void InitializeLogger();

bool WaitForEngineWaiting(ENGINE_STATE* state, const char* caller);

void IpToStr(UINT32 ip, char* buf, size_t bufLen);

UINT32 StrToIp(const char* str);