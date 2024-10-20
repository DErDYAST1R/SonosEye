#include "Write.hpp"

NTSTATUS write(PVOID target, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
	if (!target)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG(target);

	PVOID pmapped_mem = udman_spoof(MmMapIoSpaceEx)(AddrToWrite, size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	Helper::CustomMemCopy(pmapped_mem, buffer, size);

	*bytes_read = size;
	udman_spoof(MmUnmapIoSpace)(pmapped_mem, size);
	return STATUS_SUCCESS;
}

NTSTATUS Write::WriteMemory(PVOID target, PVOID buffer, SIZE_T size, UINT64 savedCR3) {
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

		ULONG64 write_size = Helper::FindMin(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);
		SIZE_T bytes_written = 0;

		NTSTATUS status = write((PVOID)currentPhysicalAddress, (PVOID)((UINT64)buffer + currentOffset), write_size, &bytes_written);

		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (bytes_written == 0) {
			break;
		}

		totalSize -= bytes_written;
		currentOffset += bytes_written;
	}

	if (!totalSize)
		return STATUS_SUCCESS;
	else
		return STATUS_UNSUCCESSFUL;
}