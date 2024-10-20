#include "Includes.hpp"

#define AttachCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ReadMemoryCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define WriteMemoryCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ProcessBaseAdressCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ModuleBaseAdressCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CR3Code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define EncryptionCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ScatterReadCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

uintptr_t CombinePointer(uint32_t high, uint32_t low) {
    return (static_cast<uint64_t>(high) << 32) | low;
}

void SplitPointer(uintptr_t pointer, uint32_t& high, uint32_t& low) {
    high = static_cast<uint32_t>(pointer >> 32); // Get the high 32 bits
    low = static_cast<uint32_t>(pointer & 0xFFFFFFFF); // Get the low 32 bits
}

// The target process we want access to.
PEPROCESS targetProcess = NULL;
UINT64 savedCR3 = NULL;
UINT64 sharedSecret = NULL;

uintptr_t ntos_image_base;
uintptr_t kernel_base;

struct attachPacket {
    HANDLE pid = NULL;
};

struct moduleBaseAdressPacket {
    const char* moduleName = NULL;
};

struct readMemoryPacket {
    PVOID targetAddress = NULL;
    PVOID bufferAddress = NULL;
    SIZE_T size = NULL;
};

struct scatterReadPacket {
    PVOID scatterReadQueueBufferAddress = NULL;
    INT size = NULL;
};

struct writeMemoryPacket {
    PVOID targetAddress = NULL;
    PVOID bufferAddress = NULL;
    SIZE_T size = NULL;
};

struct encryptionPacket {
    UINT64 xorKey = NULL;
    UINT64 publicUsermodeKey = NULL;
};

NTSTATUS Create(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return irp->IoStatus.Status;
}

NTSTATUS Close(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return irp->IoStatus.Status;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT device_object, PIRP irp) {
    SPOOF_FUNC;
    UNREFERENCED_PARAMETER(device_object);
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = irp->UserBuffer;
    PIO_STACK_LOCATION stackIrp = IoGetCurrentIrpStackLocation(irp);

    ULONG currentIoCode = stackIrp->Parameters.DeviceIoControl.IoControlCode;

    switch (stackIrp->Parameters.DeviceIoControl.IoControlCode) {

        // Attach to process
    case AttachCode:

        if (inputBuffer && outputBuffer) {
            attachPacket* inputAttachBuffer = (attachPacket*)inputBuffer;
            BOOLEAN* outputAttachBuffer = (BOOLEAN*)outputBuffer;

            if (stackIrp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(attachPacket)) {
                sharedSecret = NULL;
                if (inputAttachBuffer->pid) {
                    status = udman_spoof(PsLookupProcessByProcessId)(inputAttachBuffer->pid, &targetProcess);
                    if (NT_SUCCESS(status)) {
                        *outputAttachBuffer = TRUE; // Successfully attached
                    }
                }
            }
        }
        break;

        // Setup encryption
    case EncryptionCode:

        if (inputBuffer && outputBuffer) {
            encryptionPacket* inputEncryptionBuffer = (encryptionPacket*)inputBuffer;
            UINT64* outputEncryptionBuffer = (UINT64*)outputBuffer;

            if (stackIrp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(encryptionPacket)) {
                if (!sharedSecret)
                {
                    KeyExchange keyPair(inputEncryptionBuffer->xorKey);
                    sharedSecret = keyPair.computeSharedSecret(inputEncryptionBuffer->publicUsermodeKey);
                    *outputEncryptionBuffer = keyPair.publicKey;
                }
                else {
                    KeyExchange keyPair(sharedSecret);
                    sharedSecret = keyPair.computeSharedSecret(inputEncryptionBuffer->publicUsermodeKey);
                    *outputEncryptionBuffer = keyPair.publicKey;
                }

            }
        }

        break;

        // Get CR3 of process
    case CR3Code:

        if (outputBuffer) {
            BOOLEAN* outputCR3Buffer = (BOOLEAN*)outputBuffer;

            if (targetProcess) {
                savedCR3 = CR3::GetCR3(targetProcess);

                if (savedCR3) {
                    status = STATUS_SUCCESS;
                    *outputCR3Buffer = TRUE;
                }
            }
        }
        break;

        // Get the baseadress of a process
    case ProcessBaseAdressCode:

        if (outputBuffer && targetProcess) {
            PVOID* outputProcessBaseAdressBuffer = (PVOID*)outputBuffer;
            PVOID processBase = NULL;

            processBase = udman_spoof(PsGetProcessSectionBaseAddress)(targetProcess);

            if (processBase) {
                status = STATUS_SUCCESS;
                *outputProcessBaseAdressBuffer = (PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)processBase, sharedSecret);
            }
        }
        break;

        // Read memory from target process
    case ReadMemoryCode:

        if (inputBuffer && outputBuffer) {
            readMemoryPacket* inputReadMemoryBuffer = (readMemoryPacket*)inputBuffer;
            BOOLEAN* outputReadMemoryBuffer = (BOOLEAN*)outputBuffer;

            if (stackIrp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(readMemoryPacket)) {
                if (targetProcess && savedCR3) {
                    if (NT_SUCCESS(Read::ReadMemory((PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)inputReadMemoryBuffer->targetAddress, sharedSecret), (PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)inputReadMemoryBuffer->bufferAddress, sharedSecret), inputReadMemoryBuffer->size, savedCR3)))
                        *outputReadMemoryBuffer = TRUE;
                }
            }
        }
        break;

        // Execute a scatter read
    case ScatterReadCode:

        if (inputBuffer && outputBuffer) {
            scatterReadPacket* inputScatterReadBuffer = (scatterReadPacket*)inputBuffer;
            BOOLEAN* outputScatterReadBuffer = (BOOLEAN*)outputBuffer;

            if (stackIrp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(scatterReadPacket)) {
                if (targetProcess && savedCR3) {
                    *outputScatterReadBuffer = TRUE;
                    for (INT i = 0; i < inputScatterReadBuffer->size; i++) {
                        readMemoryPacket* packet = (readMemoryPacket*)((UINT64)inputScatterReadBuffer->scatterReadQueueBufferAddress + (i * sizeof(readMemoryPacket)));
                        if (!NT_SUCCESS(Read::ReadMemory((PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)packet->targetAddress, sharedSecret), (PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)packet->bufferAddress, sharedSecret), packet->size, savedCR3)))
                            *outputScatterReadBuffer = FALSE;
                    }
                }
            }
        }
        break;

        // Write memory from target process
    case WriteMemoryCode:

        if (inputBuffer && outputBuffer) {
            writeMemoryPacket* inputWriteMemoryBuffer = (writeMemoryPacket*)inputBuffer;
            BOOLEAN* outputWriteMemoryBuffer = (BOOLEAN*)outputBuffer;

            if (stackIrp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(writeMemoryPacket)) {
                if (targetProcess && savedCR3) {
                    if (NT_SUCCESS(Write::WriteMemory((PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)inputWriteMemoryBuffer->targetAddress, sharedSecret), (PVOID)SimpleXOREncryption::xorEncryptDecrypt((UINT64)inputWriteMemoryBuffer->bufferAddress, sharedSecret), inputWriteMemoryBuffer->size, savedCR3)))
                        *outputWriteMemoryBuffer = TRUE;
                }
            }
        }
        break;
    };

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = stackIrp->Parameters.DeviceIoControl.InputBufferLength;

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

VOID UnloadDriver(_In_ PDRIVER_OBJECT DriverObject) {

}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    SPOOF_FUNC;
    UNREFERENCED_PARAMETER(registry_path);
    ntos_image_base = NTOS::get_ntos_base_address();

    uint32_t high, low;
    uintptr_t driverObjectPointer = reinterpret_cast<uintptr_t>(driver_object);
    SplitPointer(driverObjectPointer, high, low);
    void* oDriverObject = reinterpret_cast<void*>(CombinePointer(high, low));


    UNICODE_STRING device_name = {};
    RtlInitUnicodeString(&device_name, E(L"\\Device\\SonosEyeDriver"));

    // Create driver device obj.
    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = udman_spoof(IoCreateDevice)(static_cast<PDRIVER_OBJECT>(oDriverObject), 0, &device_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    UNICODE_STRING symbolic_link = {};
    RtlInitUnicodeString(&symbolic_link, E(L"\\DosDevices\\SonosEyeDriver"));

    status = udman_spoof(IoCreateSymbolicLink)(&symbolic_link, &device_name);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    // Allow us to send small amounts of data between um/km.
    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    // Set the driver handlers to our functions with our logic.
    static_cast<PDRIVER_OBJECT>(oDriverObject)->DriverUnload = UnloadDriver;
    static_cast<PDRIVER_OBJECT>(oDriverObject)->MajorFunction[IRP_MJ_CREATE] = Create;
    static_cast<PDRIVER_OBJECT>(oDriverObject)->MajorFunction[IRP_MJ_CLOSE] = Close;
    static_cast<PDRIVER_OBJECT>(oDriverObject)->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    // We have initialized our device.
    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

    return status;
}