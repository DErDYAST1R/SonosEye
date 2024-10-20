#pragma once
#include "../Includes.hpp"

namespace Helper
{
    UINT64 TranslateLinear(UINT64 directoryTableBase, UINT64 virtualAddress);
    ULONG64 FindMin(INT32 g, SIZE_T f);
    void CustomMemCopy(const void* dstp, const void* srcp, SIZE_T len);
}