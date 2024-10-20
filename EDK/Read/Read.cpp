#include "Read.hpp"

NTSTATUS Read2(PVOID target, PVOID buffer, SIZE_T size, SIZE_T* bytesRead) {
	// Check for null pointers
	if (!target || !buffer || !bytesRead) {
		return STATUS_INVALID_PARAMETER;
	}

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG(target);

	// Map the memory
	PVOID pmapped_mem = udman_spoof(MmMapIoSpaceEx)(AddrToWrite, size, PAGE_READWRITE);
	if (!pmapped_mem) {
		return STATUS_UNSUCCESSFUL;
	}

	// Ensure size does not exceed buffer limits
	SIZE_T bytes_to_copy = min(size, PAGE_SIZE);  // Adjust based on the maximum you can read
	if (bytes_to_copy > size) {
		bytes_to_copy = size;
	}

	// Use custom memcpy with size check
	Helper::CustomMemCopy(buffer, pmapped_mem, bytes_to_copy);

	*bytesRead = size;
	udman_spoof(MmUnmapIoSpace)(pmapped_mem, size);  // Unmap the memory

	return STATUS_SUCCESS;
}

NTSTATUS Read::ReadMemory(PVOID target, PVOID buffer, SIZE_T size, UINT64 savedCR3) {
	if (!target || !buffer || !size || !savedCR3) {
		return STATUS_INVALID_PARAMETER;
	}

	SIZE_T currentOffset = 0;
	SIZE_T totalSize = size;

	while (totalSize > 0) {
		INT64 currentPhysicalAddress = Helper::TranslateLinear(savedCR3, (UINT64)target + currentOffset);
		if (!currentPhysicalAddress) {
			return STATUS_UNSUCCESSFUL;
		}

		ULONG64 readSize = Helper::FindMin(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);
		SIZE_T bytesRead = 0;

		NTSTATUS status = Read2((PVOID)currentPhysicalAddress, (PVOID)((UINT64)buffer + currentOffset), readSize, &bytesRead);

		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (!bytesRead) {
			break;
		}

		totalSize -= bytesRead;
		currentOffset += bytesRead;
	}

	if (!totalSize)
		return STATUS_SUCCESS;
	else
		return STATUS_UNSUCCESSFUL;
}