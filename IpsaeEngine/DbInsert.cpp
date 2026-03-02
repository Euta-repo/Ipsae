#include "DbInsert.h"
#include "sqlite3.h"
#include <stdio.h>
#include <unordered_set>
#include <string>
#include "Common.h"

#pragma comment(lib, "sqlite3.lib")

static int CheckDbTableList(sqlite3* db);

static int GetThreatHostList(sqlite3* db, std::unordered_set<std::string>& hosts);

// DB Insert Thread에서 사용할 DB Insert Queue입니다.
static ThreadSafeQueue<std::string> s_dbInsertQueue;

// DB에 존재해야 하는 Table 목록입니다. 이 목록에 없는 Table이 존재할 경우 DB 유효성 검사 실패로 간주합니다.
static const char* DB_LIST[] = {
	"tb_threat_host",
	"tb_access_host",
	"tb_detect_proc",
	"tb_config_host",
};

/// <summary>
/// 데이터베이스 삽입 작업을 큐에 추가합니다.
/// </summary>
/// <param name="data">삽입할 데이터 문자열.</param>
void EnqueueDbInsert(const std::string& data)
{
	s_dbInsertQueue.Push(data);
}

/// <summary>
/// 패킷 캡처 스레드를 시작하는 스레드 진입점 함수입니다.
/// </summary>
/// <param name="param">THREAD_CONTEXT 구조체에 대한 포인터로, 스레드 컨텍스트 정보를 포함합니다.</param>
/// <returns>StartDbInsert 함수의 반환 값입니다.</returns>
unsigned int __stdcall StartDbInsertThread(void* param)
{
	THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

	return StartDbInsert(context->hReadyEvent);
}

/// <summary>
/// 데이터베이스에 위협 호스트 정보를 삽입하는 스레드 함수입니다.
/// </summary>
/// <param name="hReadyEvent">스레드가 준비되었음을 알리는 이벤트 핸들입니다.</param>
/// <returns>성공 시 True, 실패 시 False를 반환합니다.</returns>
bool StartDbInsert(HANDLE hReadyEvent)
{
	sqlite3* db = NULL;
	sqlite3_stmt* stmt = NULL;
	std::unordered_set<std::string> threat_hosts;
	std::string data;

	// DB Open
	int rc = sqlite3_open("ipsaedb.db", &db);
	if (rc != SQLITE_OK)
	{
		wprintf(L"[FAIL][DbInsert] sqlite3_open: %hs\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

    // Table 점검
	if (CheckDbTableList(db) < 0)
	{
		wprintf(L"[FAIL][DbInsert] 테이블 유효성 검사 실패\n");
		sqlite3_close(db);
		return 1;
	}

	// 유해 IP 목록 수집
	if (GetThreatHostList(db, threat_hosts) < 0)
	{
		wprintf(L"[FAIL][DbInsert] 위협 호스트 목록 조회 실패\n");
		sqlite3_close(db);
		return 1;
	}

	// Main 에게 Thread 가 준비되었음을 알림
	SetEvent(hReadyEvent);

	//DB Insert Queue에서 Pop 하여 DB에 저장
	while (g_dbInsertQueue.WaitAndPop(data))
	{
		//TODO: DB에 데이터 삽입 로직 추가
	}
}

/// <summary>
/// Table 존재 여부 확인합니다.
/// </summary>
/// <param name="db">Open 된 SQLite DB 핸들</param>
/// <returns>성공 시 1, 실패 시 -1</returns>
static int CheckDbTableList(sqlite3* db)
{
	// 초기화
	sqlite3_stmt* stmt = NULL;

	// DB 유효성 검사
	if (db == NULL)
	{
		wprintf(L"[FAIL][DbInsert] Can't check DB table list: DB is NULL\n");
		return -1;
	}

	// SQL 준비
	const char* selectSql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?;";
	int rc = sqlite3_prepare_v2(db, selectSql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
	{
		wprintf(L"[FAIL][DbInsert] SELECT: %hs\n", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}

	// SQL 실행 결과 및 결과 처리
	for (auto tableName : DB_LIST)
	{		
		sqlite3_bind_text(stmt, 1, tableName, -1, SQLITE_STATIC);
		sqlite3_step(stmt);

		int exists = sqlite3_column_int(stmt, 0);
		if (exists == 0)
		{
			wprintf(L"[FAIL][DbInsert] 테이블 확인 실패: %hs\n", tableName);
			sqlite3_finalize(stmt);

			return -1;
		}

		// 다음 작업 준비
		sqlite3_reset(stmt);
	}
	
	// SQL 문 종료 및 결과 반환
	sqlite3_finalize(stmt);
	return 1;
}

/// <summary>
/// 데이터베이스에서 위협 호스트 목록을 조회합니다.
/// </summary>
/// <param name="db">SQLite 데이터베이스 연결 포인터</param>
/// <param name="hosts">조회된 위협 호스트 목록을 저장할 unordered_set 참조</param>
/// <returns>성공 시 1, 실패 시 -1</returns>
static int GetThreatHostList(sqlite3* db, std::unordered_set<std::string> &hosts)
{
	// 초기화
	sqlite3_stmt* stmt = NULL;
	std::unordered_set<std::string> threat_hosts;

	// DB 유효성 검사
	if (db == NULL)
	{
		wprintf(L"[FAIL][DbInsert] Can't check DB table list: DB is NULL\n");
		return -1;
	}

	// SQL 준비
	const char* selectSql = "SELECT host FROM tb_threat_host;";
	int rc = sqlite3_prepare_v2(db, selectSql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
	{
		wprintf(L"[FAIL][DbInsert] SELECT: %hs\n", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}

	// SQL 실행 및 결과 처리
	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		const char* host = (const char*)sqlite3_column_text(stmt, 0);
		if (host != NULL)
			threat_hosts.insert(host);
	}

	// SQL 문 종료
	sqlite3_finalize(stmt);

	// 결과 반환 - 완료 시 조회된 호스트 목록을 참조 매개변수에 저장, 실패 시 -1 반환하며 참조 매개변수는 비어있음
	hosts = std::move(threat_hosts);
	return 1;
}