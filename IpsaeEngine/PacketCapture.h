#pragma once
#include "Common.h"


void StopPacketCapture();
unsigned int StartPacketCapture(HANDLE hReadyEvent);

unsigned int __stdcall StartPacketCaptureThread(void* param);

static void FormatIPv4(UINT32 addr, char* buf, size_t bufLen);