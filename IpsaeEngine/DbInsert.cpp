#include "pch.h"
#include "DbInsert.h"
#include "sqlite3.h"
#include "Models.h"

#pragma comment(lib, "sqlite3.lib")

#pragma region Variables

static ThreadSafeQueue<DB_INSERT_BATCH> s_dbInsertQueue;

static const char* DB_LIST[] = {
    "tb_threat_host",
    "tb_network_log",
    "tb_dns_log",
    "tb_process_log",
    "tb_user_rule"
};

#pragma endregion

#pragma region Forward declaration

static int CheckDbTableList(sqlite3* db);
static int GetThreatHostList(sqlite3* db, std::unordered_set<UINT32>& hosts);
static int BatchInsertLog(sqlite3* db, DB_INSERT_BATCH& data);
static unsigned int StartDbInsert(HANDLE hReadyEvent, ENGINE_STATE* state);

#pragma endregion

#pragma region Functions

void EnqueueDbInsert(const DB_INSERT_BATCH& data)
{
    s_dbInsertQueue.Push(data);
}

unsigned int __stdcall StartDbInsertThread(void* param)
{
    THREAD_CONTEXT* context = (THREAD_CONTEXT*)param;

    return StartDbInsert(context->hReadyEvent, context->state);
}

#pragma endregion

#pragma region Static functions

static int CheckDbTableList(sqlite3* db)
{
    // 초기화
    sqlite3_stmt* stmt = NULL;

    // DB 유효성 검사
    if (db == NULL)
    {
        spdlog::error("[DbInsert] DB 연결 확인 실패: DB is NULL");
        return 1;
    }

    // SQL 준비
    const char* queryString = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?;";
    int rc = sqlite3_prepare_v2(db, queryString, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        spdlog::error("[DbInsert] SELECT: {}", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    // SQL 실행 결과 및 결과 처리
    for (auto tableName : DB_LIST)
    {
        sqlite3_bind_text(stmt, 1, tableName, -1, SQLITE_STATIC);
        sqlite3_step(stmt);

        int exists = sqlite3_column_int(stmt, 0);
        if (exists == 0)
        {
            spdlog::error("[DbInsert] 테이블 확인 실패: {}", tableName);
            sqlite3_finalize(stmt);

            return 1;
        }

        // 다음 작업 준비
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    // SQL 문 종료 및 결과 반환
    sqlite3_finalize(stmt);
    return 0;
}

static int GetThreatHostList(sqlite3* db, std::unordered_set<UINT32>& hosts)
{
    // 초기화
    sqlite3_stmt* stmt = NULL;
    std::unordered_set<UINT32> threat_hosts;

    // DB 유효성 검사
    if (db == NULL)
    {
        spdlog::error("[DbInsert] DB 연결 확인 실패: DB is NULL");
        return 1;
    }

    // SQL 준비
    const char* queryString = "SELECT host_ip FROM tb_threat_host WHERE host_type = 0 AND is_valid = 1;";
    int rc = sqlite3_prepare_v2(db, queryString, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        spdlog::error("[DbInsert] SELECT: {}", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    // SQL 실행 및 결과 처리
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        UINT32 ip = (UINT32)sqlite3_column_int(stmt, 0);
        threat_hosts.insert(ip);
    }

    // SQL 문 종료
    sqlite3_finalize(stmt);

    // 결과 반환 - 완료 시 조회된 호스트 목록을 참조 매개변수에 저장
    hosts = std::move(threat_hosts);
    return 0;
}

static int BatchInsertLog(sqlite3* db, DB_INSERT_BATCH& data)
{
    // 초기화
    sqlite3_stmt* stmtNetwork = NULL;
    sqlite3_stmt* stmtProcess = NULL;

    // DB Query 준비
    const char* queryNetwork =
        "INSERT INTO tb_network_log "
        "(direction, protocol, remote_ip, remote_port, local_port, length, is_threat, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    const char* queryProcess =
        "INSERT INTO tb_process_log "
        "(network_idx, pid, ppid, proc_name, proc_path, proc_user, proc_create, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    // SQL 준비
    if (sqlite3_prepare_v2(db, queryNetwork, -1, &stmtNetwork, NULL) != SQLITE_OK)
    {
        spdlog::error("[DbInsert] INSERT Network Log: {}", sqlite3_errmsg(db));
        return 1;
    }

    if (sqlite3_prepare_v2(db, queryProcess, -1, &stmtProcess, NULL) != SQLITE_OK)
    {
        spdlog::error("[DbInsert] INSERT Process Log: {}", sqlite3_errmsg(db));
        sqlite3_finalize(stmtNetwork);
        return 1;
    }

    // 트랜잭션 시작
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    // 데이터 배치 삽입
    for (auto & item : data)
    {
        // 네트워크 로그 정보
        const NETWORK_LOG& net = item.network;

        // SQL 바인딩
        sqlite3_bind_int(stmtNetwork, 1, net.direction);
        sqlite3_bind_int(stmtNetwork, 2, net.protocol);
        sqlite3_bind_int(stmtNetwork, 3, net.remoteIp);
        sqlite3_bind_int(stmtNetwork, 4, net.remotePort);
        sqlite3_bind_int(stmtNetwork, 5, net.localPort);
        sqlite3_bind_int(stmtNetwork, 6, net.length);
        sqlite3_bind_int(stmtNetwork, 7, net.isThreat);
        sqlite3_bind_int(stmtNetwork, 8, net.timestamp);

        // SQL 실행
        if (sqlite3_step(stmtNetwork) != SQLITE_DONE)
        {
            spdlog::error("[DbInsert] INSERT Network Log: {}", sqlite3_errmsg(db));
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            sqlite3_finalize(stmtNetwork);
            sqlite3_finalize(stmtProcess);
            return 1;
        }

        // 유해하지 않은 네트워크 로그는 프로세스 로그 저장하지 않음
        if (!net.isThreat)
        {
            sqlite3_reset(stmtNetwork);
            sqlite3_clear_bindings(stmtNetwork);
            continue;
        }

        // 방금 삽입한 네트워크 로그의 PK 값 조회
        int networkIdx = (int)sqlite3_last_insert_rowid(db);

        // 프로세스 로그 정보
        size_t proc_size = item.processes.size();
        for (size_t i = 0; i < proc_size; i++)
        {
            // SQL 바인딩
            sqlite3_bind_int(stmtProcess, 1, networkIdx);
            sqlite3_bind_int(stmtProcess, 2, item.processes[i].pid);
            sqlite3_bind_int(stmtProcess, 3, item.processes[i].ppid);
            sqlite3_bind_text(stmtProcess, 4, item.processes[i].procName.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmtProcess, 5, item.processes[i].procPath.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmtProcess, 6, item.processes[i].procUser.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmtProcess, 7, item.processes[i].procCreate);
            sqlite3_bind_int(stmtProcess, 8, item.processes[i].timestamp);

            // SQL 실행
            if (sqlite3_step(stmtProcess) != SQLITE_DONE)
            {
                spdlog::error("[DbInsert] INSERT Process Log: {}", sqlite3_errmsg(db));
                sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
                sqlite3_finalize(stmtNetwork);
                sqlite3_finalize(stmtProcess);
                return 1;
            }

            // Process 다음 작업 준비
            sqlite3_reset(stmtProcess);
            sqlite3_clear_bindings(stmtProcess);
        }

        // Network 다음 작업 준비
        sqlite3_reset(stmtNetwork);
        sqlite3_clear_bindings(stmtNetwork);
    }

    // 트랜잭션 커밋
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    // SQL 문 종료
    sqlite3_finalize(stmtNetwork);
    sqlite3_finalize(stmtProcess);

    return 0;
}

static unsigned int StartDbInsert(HANDLE hReadyEvent, ENGINE_STATE* state)
{
    sqlite3* db = NULL;

    std::unordered_set<UINT32> threat_hosts;
    DB_INSERT_BATCH data;

    // DB Open
    int rc = sqlite3_open("ipsaedb.db", &db);
    if (rc != SQLITE_OK)
    {
        spdlog::error("[DbInsert] sqlite3_open: {}", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Table 점검
    if (CheckDbTableList(db) > 0)
    {
        spdlog::error("[DbInsert] 테이블 확인 실패");
        sqlite3_close(db);
        return 1;
    }

    // 유해 IP 목록 수집
    if (GetThreatHostList(db, threat_hosts) > 0)
    {
        spdlog::error("[DbInsert] 유해 호스트 목록 조회 실패");
        sqlite3_close(db);
        return 1;
    }

    // Main 에게 Thread 가 준비되었음을 알림
    state->dbInsertRunning = true;
    SetEvent(hReadyEvent);

    //DB Insert Queue에서 Pop 하여 DB에 저장
    while (s_dbInsertQueue.WaitAndPop(data))
    {
        // 엔진 대기 상태 처리
        if (!WaitForEngineWaiting(state, "DbInsert"))
            break;

        // 엔진 오류 상태 처리
        if (state->status == ENGINE_ERROR)
        {
            spdlog::error("[DbInsert] 엔진이 강제 종료됩니다.");
            break;
        }


        // 로그 배치 삽입
        if (BatchInsertLog(db, data) > 0)
        {
            spdlog::error("[DbInsert] 로그 배치 삽입 실패");
            continue;
        }

        // 엔진 중지 상태 처리
        if (state->status == ENGINE_STOPPED || state->status == ENGINE_STOPPING)
        {
            break;
        }
    }

    // 엔진 중지 상태에서 대기 중인 로그 배치 삽입 처리
    if (state->status == ENGINE_STOPPING || state->status == ENGINE_STOPPED)
    {
        s_dbInsertQueue.Stop();
        DWORD64 startTime = GetTickCount64();

        while (s_dbInsertQueue.TryPop(data))
        {
            if (GetTickCount64() - startTime > TIMEOUT_STOPPING)
            {
                spdlog::warn("[DbInsert] 대기 시간 초과로 로그 배치 삽입을 중단합니다. 남은 큐 크기: {}", s_dbInsertQueue.queue.size());
                break;
            }
            if (BatchInsertLog(db, data) > 0)
            {
                spdlog::error("[DbInsert] 로그 배치 삽입 실패");
                continue;
            }
        }
        spdlog::info("[DbInsert] 로그 배치 삽입 스레드 정상 종료");
    }

    // DB Close 및 종료
    sqlite3_close(db);
    state->dbInsertRunning = false;
    return 0;
}

#pragma endregion
