#pragma once
#include "Common.h"
#include "Models.h"

void EnqueueInspect(const std::unordered_set<UINT32>& data);

unsigned int __stdcall StartInspectorThread(void* param);