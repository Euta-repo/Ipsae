#pragma once

#include <Windows.h>

struct THREAD_CONTEXT
{
	int ThreadId;
	HANDLE hReadyEvent;
};

typedef unsigned int(__stdcall* THREAD_FUNC)(void*);