#pragma once
#include "Common.h"

unsigned int __stdcall StartDbInsertThread(void* param);

bool StartDbInsert(HANDLE hReadyEvent);

void EnqueueDbInsert(const std::string& data);