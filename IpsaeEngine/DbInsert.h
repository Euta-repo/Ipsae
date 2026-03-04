#pragma once
#include "Common.h"
#include "Models.h"

unsigned int __stdcall StartDbInsertThread(void* param);

void EnqueueDbInsert(const DB_INSERT_BATCH& data);