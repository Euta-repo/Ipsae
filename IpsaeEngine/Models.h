#pragma once
#include "pch.h"

// =============================================================================================
// tb_threat_host
// =============================================================================================

struct THREAT_HOST
{
    int idx;
    int hostType;
    UINT32 hostIp;          // unsigned
    std::string hostDomain;
    std::string source;
    int isValid;
    int createDate;
    int lastDate;
    int threatLevel;
};

// =============================================================================================
// tb_network_log
// =============================================================================================

struct NETWORK_LOG
{
    int idx;
    int direction;      // 0: IN, 1: OUT
    int protocol;       // 6: TCP, 17: UDP
    UINT32 remoteIp;
    UINT16 remotePort;
    UINT16 localPort;
    UINT16 length;
    int isThreat;       // 0: false, 1: true
    int timestamp;
};

// =============================================================================================
// tb_process_log
// =============================================================================================

struct PROCESS_LOG
{
    int idx;
    int networkIdx;     // tb_network_log PK
    DWORD pid;
    DWORD ppid;
    std::string procName;
    std::string procPath;
    std::string procUser;
    int procCreate;     // timestamp
    int timestamp;
};

// =============================================================================================
// tb_user_rule
// =============================================================================================

struct USER_RULE
{
    int idx;
    int ruleType;       // 0: blacklist, 1: whitelist
    int ruleTarget;     // 0: ip, 1: proc, 2: port
    std::string ruleValue;
    std::string ruleReason;
    int isValid;        // 0: false, 1: true
    int timestamp;
};

// =============================================================================================
// Inspector -> DbInsert 전달용
// =============================================================================================

struct DB_INSERT_DATA
{
    NETWORK_LOG network;
    std::vector<PROCESS_LOG> processes;
};

typedef std::vector<DB_INSERT_DATA> DB_INSERT_BATCH;