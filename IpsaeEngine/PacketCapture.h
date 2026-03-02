#pragma once
#include <Windows.h>
#include "Common.h"


bool StartPacketCapture(HANDLE hReadyEvent);

void StopPacketCapture();

unsigned int __stdcall StartPacketCaptureThread(void* param);