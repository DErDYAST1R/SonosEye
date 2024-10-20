#pragma once
#include "../Includes.hpp"

namespace Write
{
	NTSTATUS WriteMemory(PVOID target, PVOID buffer, SIZE_T size, UINT64 savedCR3);
}