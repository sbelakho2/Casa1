//! Kernel API shim table (`DriverShim`) and its dispatch-table metadata.

use super::*;

/// One kernel API exported by the island's shim table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverShim {
    DbgPrint,
    IoCreateDevice,
    IoDeleteDevice,
    IoCreateSymbolicLink,
    IoDeleteSymbolicLink,
    IoAllocateIrp,
    IoFreeIrp,
    RtlInitUnicodeString,
    IofCompleteRequest,
    IoCompleteRequest,
    ExAllocatePoolWithTag,
    ExFreePoolWithTag,
    /// `ExAllocatePool` (untagged, typed pool).
    ExAllocatePool,
    /// `ExFreePool` (untagged pool free).
    ExFreePool,
    /// `KeGetCurrentIrql`.
    KeGetCurrentIrql,
    /// `KfRaiseIrql`.
    KfRaiseIrql,
    /// `KfLowerIrql`; drains queued DPCs below dispatch level.
    KfLowerIrql,
    /// `KeAcquireSpinLockRaiseToDpc`.
    KeAcquireSpinLockRaiseToDpc,
    /// `KeReleaseSpinLock`.
    KeReleaseSpinLock,
    /// `KeInitializeDpc`.
    KeInitializeDpc,
    /// `KeInsertQueueDpc`.
    KeInsertQueueDpc,
    /// `KeRemoveQueueDpc`.
    KeRemoveQueueDpc,
    /// `KeInitializeEvent`.
    KeInitializeEvent,
    /// `KeSetEvent`.
    KeSetEvent,
    /// `KeResetEvent`.
    KeResetEvent,
    /// `KeReadStateEvent`.
    KeReadStateEvent,
    /// `KeWaitForSingleObject`.
    KeWaitForSingleObject,
    /// `KeQuerySystemTime`.
    KeQuerySystemTime,
    /// `IoAllocateMdl`.
    IoAllocateMdl,
    /// `MmProbeAndLockPages`.
    MmProbeAndLockPages,
    /// `MmUnlockPages`.
    MmUnlockPages,
    /// `IoFreeMdl`.
    IoFreeMdl,
    /// `MmGetMdlByteCount`.
    MmGetMdlByteCount,
    /// `PsGetCurrentProcessId`.
    PsGetCurrentProcessId,
    /// `PsGetCurrentThreadId`.
    PsGetCurrentThreadId,
    /// `ZwOpenKey`.
    ZwOpenKey,
    /// `ZwQueryValueKey`.
    ZwQueryValueKey,
    /// `ZwClose` for island registry key handles.
    ZwClose,
    /// `ExInitializeNPagedLookasideList`.
    ExInitializeNPagedLookasideList,
    /// `ExAllocateFromNPagedLookasideList`.
    ExAllocateFromNPagedLookasideList,
    /// `ExFreeToNPagedLookasideList`.
    ExFreeToNPagedLookasideList,
    /// `ExInitializePagedLookasideList`.
    ExInitializePagedLookasideList,
    /// `ExAllocateFromPagedLookasideList`.
    ExAllocateFromPagedLookasideList,
    /// `ExFreeToPagedLookasideList`.
    ExFreeToPagedLookasideList,
    /// Creates a real guest-executable island system thread.
    PsCreateSystemThread,
    /// Terminates the calling system thread.
    PsTerminateSystemThread,
    /// Connects a virtual line-based interrupt.
    IoConnectInterrupt,
    /// Connects an interrupt through the extended parameter block.
    IoConnectInterruptEx,
    /// Disconnects a virtual interrupt object.
    IoDisconnectInterrupt,
    /// Registers an in-process ETW provider.
    EtwRegister,
    /// Unregisters an in-process ETW provider.
    EtwUnregister,
    /// Writes an event to an in-process ETW provider.
    EtwWrite,
    /// Connects to an in-process ALPC port.
    NtAlpcConnectPort,
    /// Queries the executive interrupt-time counter.
    KeQueryInterruptTime,
    /// Guest-visible preemption safepoint.
    IslandSafepoint,
    /// Default `MajorFunction` dispatch: refuses unsupported IRPs.
    IrpDispatch,
    /// KMDF subset: `WdfDriverCreate`.
    WdfDriverCreate,
    /// KMDF subset: `WdfDeviceInitSetDeviceType`.
    WdfDeviceInitSetDeviceType,
    /// KMDF subset: `WdfDeviceInitSetIoType`.
    WdfDeviceInitSetIoType,
    /// KMDF subset: `WdfDeviceInitAssignName`.
    WdfDeviceInitAssignName,
    /// KMDF subset: `WdfDeviceCreate`.
    WdfDeviceCreate,
    /// KMDF subset: `WdfIoQueueCreate`.
    WdfIoQueueCreate,
    /// KMDF subset: `WdfRequestCreate`.
    WdfRequestCreate,
    /// KMDF subset: `WdfRequestFormatRequestForIoctl`.
    WdfRequestFormatRequestForIoctl,
    /// KMDF subset: `WdfRequestRetrieveInputBuffer`.
    WdfRequestRetrieveInputBuffer,
    /// KMDF subset: `WdfRequestRetrieveOutputBuffer`.
    WdfRequestRetrieveOutputBuffer,
    /// KMDF subset: `WdfRequestComplete`.
    WdfRequestComplete,
    /// KMDF subset: `WdfRequestCompleteWithInformation`.
    WdfRequestCompleteWithInformation,
    /// KMDF subset: `WdfDeviceWdmGetDeviceObject`.
    WdfDeviceWdmGetDeviceObject,
    /// KMDF subset: `WdfObjectGetTypedContext` (and its Worker form).
    WdfObjectGetTypedContext,
    /// KMDF subset: `WdfObjectDelete`.
    WdfObjectDelete,
    /// KMDF subset: `WdfWaitLockCreate`.
    WdfWaitLockCreate,
    /// KMDF subset: `WdfWaitLockAcquire`.
    WdfWaitLockAcquire,
    /// KMDF subset: `WdfWaitLockRelease`.
    WdfWaitLockRelease,
    /// KMDF subset: `WdfObjectAllocateContext`.
    WdfObjectAllocateContext,
    /// KMDF subset: `WdfDeviceGetIoTarget`.
    WdfDeviceGetIoTarget,
    /// KMDF subset: `WdfIoTargetCreate`.
    WdfIoTargetCreate,
    /// KMDF subset: `WdfIoTargetSendIoctlSynchronously`.
    WdfIoTargetSendIoctlSynchronously,
    /// KMDF subset: `WdfIoTargetFormatRequestForIoctl`.
    WdfIoTargetFormatRequestForIoctl,
    /// KMDF subset: `WdfRequestSend`.
    WdfRequestSend,
    /// KMDF subset: `WdfRequestCancelQueuedRequest`.
    WdfRequestCancelQueuedRequest,
    /// KMDF subset: `WdfIoQueueRetrieveNextRequest`.
    WdfIoQueueRetrieveNextRequest,
    /// KMDF subset: `WdfIoQueueRetrieveFoundRequest`.
    WdfIoQueueRetrieveFoundRequest,
    /// KMDF subset: `WdfIoQueueStop`.
    WdfIoQueueStop,
    /// KMDF subset: `WdfIoQueueStopSynchronously`.
    WdfIoQueueStopSynchronously,
    /// KMDF subset: `WdfIoQueueDrain`.
    WdfIoQueueDrain,
    /// KMDF subset: `WdfIoQueueDrainSynchronously`.
    WdfIoQueueDrainSynchronously,
    /// KMDF subset: `WdfIoQueuePurge`.
    WdfIoQueuePurge,
    /// KMDF subset: `WdfIoQueuePurgeSynchronously`.
    WdfIoQueuePurgeSynchronously,
    /// KMDF subset: `WdfIoQueueStart`.
    WdfIoQueueStart,
    /// Framework-installed `IRP_MJ_READ` dispatch.
    WdfEvtIoReadDispatch,
    /// Framework-installed `IRP_MJ_WRITE` dispatch.
    WdfEvtIoWriteDispatch,
    /// Framework-installed `IRP_MJ_DEVICE_CONTROL` dispatch that delivers the
    /// current IRP to the device's queue callback.
    WdfEvtIoDeviceControlDispatch,
    /// Framework-installed `IRP_MJ_CLEANUP` dispatch.
    WdfEvtIoCleanupDispatch,
    /// Framework-installed `IRP_MJ_CLOSE` dispatch.
    WdfEvtIoCloseDispatch,
    /// KMDF subset: `WdfDeviceInitSetPnpPowerEventCallbacks`.
    WdfDeviceInitSetPnpPowerEventCallbacks,
    /// KMDF subset: `WdfDeviceInitSetFileObjectConfig`.
    WdfDeviceInitSetFileObjectConfig,
    /// KMDF subset: `WdfMemoryCreate`.
    WdfMemoryCreate,
    /// KMDF subset: `WdfMemoryCreatePreallocated`.
    WdfMemoryCreatePreallocated,
    /// KMDF subset: `WdfMemoryGetBuffer`.
    WdfMemoryGetBuffer,
    /// KMDF subset: `WdfStringCreate`.
    WdfStringCreate,
    /// KMDF subset: `WdfStringGetUnicodeString`.
    WdfStringGetUnicodeString,
    /// KMDF subset: `WdfDeviceEnqueueRequest`.
    WdfDeviceEnqueueRequest,
    /// KMDF subset: `WdfPdoInitAllocate`.
    WdfPdoInitAllocate,
    /// KMDF subset: `WdfPdoInitAssignDeviceID`.
    WdfPdoInitAssignDeviceID,
    /// KMDF subset: `WdfPdoInitAssignInstanceID`.
    WdfPdoInitAssignInstanceID,
    /// KMDF subset: `WdfPdoInitAddHardwareID`.
    WdfPdoInitAddHardwareID,
    /// KMDF subset: `WdfPdoInitAddCompatibleID`.
    WdfPdoInitAddCompatibleID,
    /// KMDF subset: `WdfSpinLockCreate`.
    WdfSpinLockCreate,
    /// KMDF subset: `WdfSpinLockAcquire`.
    WdfSpinLockAcquire,
    /// KMDF subset: `WdfSpinLockRelease`.
    WdfSpinLockRelease,
    /// KMDF subset: `WdfTimerCreate`.
    WdfTimerCreate,
    /// KMDF subset: `WdfTimerStart`.
    WdfTimerStart,
    /// KMDF subset: `WdfTimerStop`.
    WdfTimerStop,
    /// KMDF subset: `WdfWorkItemCreate`.
    WdfWorkItemCreate,
    /// KMDF subset: `WdfWorkItemEnqueue`.
    WdfWorkItemEnqueue,
    /// KMDF subset: `WdfWorkItemFlush`.
    WdfWorkItemFlush,
    /// KMDF subset: `WdfRequestFormatRequestForRead`.
    WdfRequestFormatRequestForRead,
    /// KMDF subset: `WdfRequestFormatRequestForWrite`.
    WdfRequestFormatRequestForWrite,
    /// KMDF subset: `WdfRequestGetStatus`.
    WdfRequestGetStatus,
    /// KMDF subset: `WdfRequestIsCanceled`.
    WdfRequestIsCanceled,
    /// KMDF subset: `WdfRequestMarkCancelable`.
    WdfRequestMarkCancelable,
    /// KMDF subset: `WdfRequestUnmarkCancelable`.
    WdfRequestUnmarkCancelable,
    /// KMDF subset: `WdfDeviceStopIdle`.
    WdfDeviceStopIdle,
    /// KMDF subset: `WdfDeviceResumeIdle`.
    WdfDeviceResumeIdle,
    /// KMDF subset: `WdfRequestForwardToIoQueue`.
    WdfRequestForwardToIoQueue,
    /// KMDF subset: `WdfDeviceInitSetPowerPolicyOwnership`.
    WdfDeviceInitSetPowerPolicyOwnership,
    /// KMDF subset: `WdfCollectionCreate`.
    WdfCollectionCreate,
    /// KMDF subset: `WdfCollectionAdd`.
    WdfCollectionAdd,
    /// KMDF subset: `WdfCollectionRemove`.
    WdfCollectionRemove,
    /// KMDF subset: `WdfCollectionRemoveAll`.
    WdfCollectionRemoveAll,
    /// KMDF subset: `WdfCollectionGetItem`.
    WdfCollectionGetItem,
    /// KMDF subset: `WdfCollectionGetCount`.
    WdfCollectionGetCount,
    /// KMDF subset: `WdfCollectionContains2`.
    WdfCollectionContains2,
    /// KMDF subset: `WdfLookasideListCreate`.
    WdfLookasideListCreate,
    /// KMDF subset: `WdfMemoryCreateFromLookaside`.
    WdfMemoryCreateFromLookaside,
    /// KMDF subset: `WdfInterruptCreate`.
    WdfInterruptCreate,
    /// KMDF subset: `WdfInterruptQueueDpcForIsr`.
    WdfInterruptQueueDpcForIsr,
    /// KMDF subset: `WdfInterruptAcquireLock`.
    WdfInterruptAcquireLock,
    /// KMDF subset: `WdfInterruptReleaseLock`.
    WdfInterruptReleaseLock,
    /// KMDF subset: `WdfInterruptSynchronize`.
    WdfInterruptSynchronize,
    /// KMDF subset: `WdfInterruptDisable`.
    WdfInterruptDisable,
    /// KMDF subset: `WdfInterruptEnable`.
    WdfInterruptEnable,
    /// KMDF subset: `WdfDmaEnablerCreate`.
    WdfDmaEnablerCreate,
    /// KMDF subset: `WdfDmaEnablerCalculateMaximumTransferSize`.
    WdfDmaEnablerCalculateMaximumTransferSize,
    /// KMDF subset: `WdfDmaTransactionCreate`.
    WdfDmaTransactionCreate,
    /// KMDF subset: `WdfDmaTransactionInitialize`.
    WdfDmaTransactionInitialize,
    /// KMDF subset: `WdfDmaTransactionExecute`.
    WdfDmaTransactionExecute,
    /// KMDF subset: `WdfDmaTransactionRelease`.
    WdfDmaTransactionRelease,
    /// KMDF subset: `WdfDmaTransactionCancel`.
    WdfDmaTransactionCancel,
    /// KMDF subset: `WdfUsbTargetDeviceCreate`.
    WdfUsbTargetDeviceCreate,
    /// KMDF subset: `WdfUsbTargetDeviceGetInformation`.
    WdfUsbTargetDeviceGetInformation,
    /// KMDF subset: `WdfUsbInterfaceGetConfiguredPipe`.
    WdfUsbInterfaceGetConfiguredPipe,
    /// KMDF subset: `WdfUsbTargetPipeReadPipe`.
    WdfUsbTargetPipeReadPipe,
    /// KMDF subset: `WdfUsbTargetPipeWritePipe`.
    WdfUsbTargetPipeWritePipe,
    /// KMDF subset: `WdfUsbTargetPipeAbortPipe`.
    WdfUsbTargetPipeAbortPipe,
    /// KMDF subset: `WdfUsbTargetPipeResetPipe`.
    WdfUsbTargetPipeResetPipe,
    /// KMDF subset: `WdfUsbTargetPipeGetType`.
    WdfUsbTargetPipeGetType,
    /// KMDF subset: `WdfRegistryOpenKey`.
    WdfRegistryOpenKey,
    /// KMDF subset: `WdfRegistryCreateKey`.
    WdfRegistryCreateKey,
    /// KMDF subset: `WdfRegistryClose`.
    WdfRegistryClose,
    /// KMDF subset: `WdfRegistryQueryValue`.
    WdfRegistryQueryValue,
    /// KMDF subset: `WdfRegistryAssignValue` (`WdfRegistrySetValue` alias).
    WdfRegistryAssignValue,
    /// KMDF subset: `WdfRegistryDeleteValue`.
    WdfRegistryDeleteValue,
    /// KMDF subset: `WdfChildListCreate`.
    WdfChildListCreate,
    /// KMDF subset: `WdfChildListGetFirst`.
    WdfChildListGetFirst,
    /// KMDF subset: `WdfChildListGetNext`.
    WdfChildListGetNext,
    /// KMDF subset: `WdfChildListGetChildCount`.
    WdfChildListGetChildCount,
    /// Framework bus-relation scan: runs `EvtChildListEnumerateChildren`
    /// over a child list and applies the PnP arrival/removal diff.
    WdfEvtChildListScanDispatch,
    /// KMDF subset: `WdfCmResourceListCreate`.
    WdfCmResourceListCreate,
    /// KMDF subset: `WdfCmResourceListGetDescriptor`.
    WdfCmResourceListGetDescriptor,
    /// KMDF subset: `WdfCmResourceListGetCount`.
    WdfCmResourceListGetCount,
    /// KMDF subset: `WdfMemoryCopy`.
    WdfMemoryCopy,
    /// KMDF subset: `WdfMemoryAssign`.
    WdfMemoryAssign,
    /// KMDF subset: `WdfRequestCreateFromIrp`.
    WdfRequestCreateFromIrp,
    /// KMDF subset: `WdfRequestImpersonate`.
    WdfRequestImpersonate,
    /// KMDF subset: `WdfRequestStopImpersonating`.
    WdfRequestStopImpersonating,
    /// KMDF subset: `WdfRequestWdmGetIrp`.
    WdfRequestWdmGetIrp,
    /// KMDF subset: `WdfRequestSetInformation`.
    WdfRequestSetInformation,
    /// KMDF subset: `WdfRequestForwardToParentDeviceIoQueue`.
    WdfRequestForwardToParentDeviceIoQueue,
    /// KMDF subset: `WdfObjectReference`.
    WdfObjectReference,
    /// KMDF subset: `WdfObjectDereference`.
    WdfObjectDereference,
    /// KMDF subset: `WdfControlDeviceInitAllocate`.
    WdfControlDeviceInitAllocate,
    /// KMDF subset: `WdfControlFinishInitializing`.
    WdfControlFinishInitializing,
    /// Framework-installed `IRP_MJ_PNP` dispatch.
    WdfEvtPnpDispatch,
    /// Framework-installed `IRP_MJ_POWER` dispatch.
    WdfEvtPowerDispatch,
}

impl DriverShim {
    pub(crate) fn for_import(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "dbgprint" => Some(Self::DbgPrint),
            "iocreatedevice" => Some(Self::IoCreateDevice),
            "iodeletedevice" => Some(Self::IoDeleteDevice),
            "iocreatesymboliclink" => Some(Self::IoCreateSymbolicLink),
            "iodeletesymboliclink" => Some(Self::IoDeleteSymbolicLink),
            "ioallocateirp" => Some(Self::IoAllocateIrp),
            "iofreeirp" => Some(Self::IoFreeIrp),
            "rtlinitunicodestring" => Some(Self::RtlInitUnicodeString),
            "iofcompleterequest" => Some(Self::IofCompleteRequest),
            "iocompleterequest" => Some(Self::IoCompleteRequest),
            "exallocatepoolwithtag" => Some(Self::ExAllocatePoolWithTag),
            "exfreepoolwithtag" => Some(Self::ExFreePoolWithTag),
            "exallocatepool" => Some(Self::ExAllocatePool),
            "exfreepool" => Some(Self::ExFreePool),
            "kegetcurrentirql" => Some(Self::KeGetCurrentIrql),
            "kfraiseirql" => Some(Self::KfRaiseIrql),
            "kflowerirql" => Some(Self::KfLowerIrql),
            "keacquirespinlockraisetodpc" => Some(Self::KeAcquireSpinLockRaiseToDpc),
            "kereleasespinlock" => Some(Self::KeReleaseSpinLock),
            "keinitializedpc" => Some(Self::KeInitializeDpc),
            "keinsertqueuedpc" => Some(Self::KeInsertQueueDpc),
            "keremovequeuedpc" => Some(Self::KeRemoveQueueDpc),
            "keinitializeevent" => Some(Self::KeInitializeEvent),
            "kesetevent" => Some(Self::KeSetEvent),
            "keresetevent" => Some(Self::KeResetEvent),
            "kereadstateevent" => Some(Self::KeReadStateEvent),
            "kewaitforsingleobject" => Some(Self::KeWaitForSingleObject),
            "kequerysystemtime" => Some(Self::KeQuerySystemTime),
            "ioallocatemdl" => Some(Self::IoAllocateMdl),
            "mmprobeandlockpages" => Some(Self::MmProbeAndLockPages),
            "mmunlockpages" => Some(Self::MmUnlockPages),
            "iofreemdl" => Some(Self::IoFreeMdl),
            "mmgetmdlbytecount" => Some(Self::MmGetMdlByteCount),
            "psgetcurrentprocessid" => Some(Self::PsGetCurrentProcessId),
            "psgetcurrentthreadid" => Some(Self::PsGetCurrentThreadId),
            "zwopenkey" => Some(Self::ZwOpenKey),
            "zwqueryvaluekey" => Some(Self::ZwQueryValueKey),
            "zwclose" => Some(Self::ZwClose),
            "exinitializenpagedlookasidelist" => Some(Self::ExInitializeNPagedLookasideList),
            "exallocatefromnpagedlookasidelist" => Some(Self::ExAllocateFromNPagedLookasideList),
            "exfreetonpagedlookasidelist" => Some(Self::ExFreeToNPagedLookasideList),
            "exinitializepagedlookasidelist" => Some(Self::ExInitializePagedLookasideList),
            "exallocatefrompagedlookasidelist" => Some(Self::ExAllocateFromPagedLookasideList),
            "exfreetopagedlookasidelist" => Some(Self::ExFreeToPagedLookasideList),
            "pscreatesystemthread" => Some(Self::PsCreateSystemThread),
            "psterminatesystemthread" => Some(Self::PsTerminateSystemThread),
            "ioconnectinterrupt" => Some(Self::IoConnectInterrupt),
            "ioconnectinterruptex" => Some(Self::IoConnectInterruptEx),
            "iodisconnectinterrupt" => Some(Self::IoDisconnectInterrupt),
            "etwregister" => Some(Self::EtwRegister),
            "etwunregister" => Some(Self::EtwUnregister),
            "etwwrite" => Some(Self::EtwWrite),
            "ntalpcconnectport" => Some(Self::NtAlpcConnectPort),
            "kequeryinterrupttime" => Some(Self::KeQueryInterruptTime),
            "islandsafepoint" => Some(Self::IslandSafepoint),
            "wdfdrivercreate" => Some(Self::WdfDriverCreate),
            "wdfdeviceinitsetdevicetype" => Some(Self::WdfDeviceInitSetDeviceType),
            "wdfdeviceinitsetiotype" => Some(Self::WdfDeviceInitSetIoType),
            "wdfdeviceinitassignname" => Some(Self::WdfDeviceInitAssignName),
            "wdfdevicecreate" => Some(Self::WdfDeviceCreate),
            "wdfioqueuecreate" => Some(Self::WdfIoQueueCreate),
            "wdfrequestcreate" => Some(Self::WdfRequestCreate),
            "wdfrequestformatrequestforioctl" => Some(Self::WdfRequestFormatRequestForIoctl),
            "wdfrequestretrieveinputbuffer" => Some(Self::WdfRequestRetrieveInputBuffer),
            "wdfrequestretrieveoutputbuffer" => Some(Self::WdfRequestRetrieveOutputBuffer),
            "wdfrequestcomplete" => Some(Self::WdfRequestComplete),
            "wdfrequestcompletewithinformation" => Some(Self::WdfRequestCompleteWithInformation),
            "wdfdevicewdmgetdeviceobject" => Some(Self::WdfDeviceWdmGetDeviceObject),
            "wdfobjectgettypedcontext" | "wdfobjectgettypedcontextworker" => {
                Some(Self::WdfObjectGetTypedContext)
            }
            "wdfobjectdelete" => Some(Self::WdfObjectDelete),
            "wdfwaitlockcreate" => Some(Self::WdfWaitLockCreate),
            "wdfwaitlockacquire" => Some(Self::WdfWaitLockAcquire),
            "wdfwaitlockrelease" => Some(Self::WdfWaitLockRelease),
            "wdfobjectallocatecontext" => Some(Self::WdfObjectAllocateContext),
            "wdfdevicegetiotarget" => Some(Self::WdfDeviceGetIoTarget),
            "wdfiotargetcreate" => Some(Self::WdfIoTargetCreate),
            "wdfiotargetsendioctlsynchronously" => Some(Self::WdfIoTargetSendIoctlSynchronously),
            "wdfiotargetformatrequestforioctl" => Some(Self::WdfIoTargetFormatRequestForIoctl),
            "wdfrequestsend" => Some(Self::WdfRequestSend),
            "wdfrequestcancelqueuedrequest" => Some(Self::WdfRequestCancelQueuedRequest),
            "wdfioqueueretrievenextrequest" => Some(Self::WdfIoQueueRetrieveNextRequest),
            "wdfioqueueretrievefoundrequest" => Some(Self::WdfIoQueueRetrieveFoundRequest),
            "wdfioqueuestop" => Some(Self::WdfIoQueueStop),
            "wdfioqueuestopsynchronously" => Some(Self::WdfIoQueueStopSynchronously),
            "wdfioqueuedrain" => Some(Self::WdfIoQueueDrain),
            "wdfioqueuedrainsynchronously" => Some(Self::WdfIoQueueDrainSynchronously),
            "wdfioqueuepurge" => Some(Self::WdfIoQueuePurge),
            "wdfioqueuepurgesynchronously" => Some(Self::WdfIoQueuePurgeSynchronously),
            "wdfioqueuestart" => Some(Self::WdfIoQueueStart),
            "wdfdeviceinitsetpnppowereventcallbacks" => {
                Some(Self::WdfDeviceInitSetPnpPowerEventCallbacks)
            }
            "wdfdeviceinitsetfileobjectconfig" => Some(Self::WdfDeviceInitSetFileObjectConfig),
            "wdfmemorycreate" => Some(Self::WdfMemoryCreate),
            "wdfmemorycreatepreallocated" => Some(Self::WdfMemoryCreatePreallocated),
            "wdfmemorygetbuffer" => Some(Self::WdfMemoryGetBuffer),
            "wdfmemorydelete" => Some(Self::WdfObjectDelete),
            "wdfstringcreate" => Some(Self::WdfStringCreate),
            "wdfstringgetunicodestring" => Some(Self::WdfStringGetUnicodeString),
            "wdfstringdelete" => Some(Self::WdfObjectDelete),
            "wdfdeviceenqueuerequest" => Some(Self::WdfDeviceEnqueueRequest),
            "wdfpdoinitallocate" => Some(Self::WdfPdoInitAllocate),
            "wdfpdoinitassigndeviceid" => Some(Self::WdfPdoInitAssignDeviceID),
            "wdfpdoinitassigninstanceid" => Some(Self::WdfPdoInitAssignInstanceID),
            "wdfpdoinitaddhardwareid" => Some(Self::WdfPdoInitAddHardwareID),
            "wdfpdoinitaddcompatibleid" => Some(Self::WdfPdoInitAddCompatibleID),
            "wdfspinlockcreate" => Some(Self::WdfSpinLockCreate),
            "wdfspinlockacquire" => Some(Self::WdfSpinLockAcquire),
            "wdfspinlockrelease" => Some(Self::WdfSpinLockRelease),
            "wdftimercreate" => Some(Self::WdfTimerCreate),
            "wdftimerstart" => Some(Self::WdfTimerStart),
            "wdftimerstop" => Some(Self::WdfTimerStop),
            "wdfworkitemcreate" => Some(Self::WdfWorkItemCreate),
            "wdfworkitemenqueue" => Some(Self::WdfWorkItemEnqueue),
            "wdfworkitemflush" => Some(Self::WdfWorkItemFlush),
            "wdfrequestformatrequestforread" => Some(Self::WdfRequestFormatRequestForRead),
            "wdfrequestformatrequestforwrite" => Some(Self::WdfRequestFormatRequestForWrite),
            "wdfrequestgetstatus" => Some(Self::WdfRequestGetStatus),
            "wdfrequestiscanceled" => Some(Self::WdfRequestIsCanceled),
            "wdfrequestmarkcancelable" => Some(Self::WdfRequestMarkCancelable),
            "wdfrequestunmarkcancelable" => Some(Self::WdfRequestUnmarkCancelable),
            "wdfdevicestopidle" => Some(Self::WdfDeviceStopIdle),
            "wdfdeviceresumeidle" => Some(Self::WdfDeviceResumeIdle),
            "wdfrequestforwardtoioqueue" => Some(Self::WdfRequestForwardToIoQueue),
            "wdfdeviceinitsetpowerpolicyownership" => {
                Some(Self::WdfDeviceInitSetPowerPolicyOwnership)
            }
            "wdfcollectioncreate" => Some(Self::WdfCollectionCreate),
            "wdfcollectionadd" => Some(Self::WdfCollectionAdd),
            "wdfcollectionremove" => Some(Self::WdfCollectionRemove),
            "wdfcollectionremoveall" => Some(Self::WdfCollectionRemoveAll),
            "wdfcollectiongetitem" => Some(Self::WdfCollectionGetItem),
            "wdfcollectiongetcount" => Some(Self::WdfCollectionGetCount),
            "wdfcollectioncontains" | "wdfcollectioncontains2" => {
                Some(Self::WdfCollectionContains2)
            }
            "wdflookasidelistcreate" => Some(Self::WdfLookasideListCreate),
            "wdfmemorycreatefromlookaside" => Some(Self::WdfMemoryCreateFromLookaside),
            "wdfinterruptcreate" => Some(Self::WdfInterruptCreate),
            "wdfinterruptqueuedpcforisr" => Some(Self::WdfInterruptQueueDpcForIsr),
            "wdfinterruptacquirelock" => Some(Self::WdfInterruptAcquireLock),
            "wdfinterruptreleaselock" => Some(Self::WdfInterruptReleaseLock),
            "wdfinterruptsynchronize" => Some(Self::WdfInterruptSynchronize),
            "wdfinterruptdisable" => Some(Self::WdfInterruptDisable),
            "wdfinterruptenable" => Some(Self::WdfInterruptEnable),
            "wdfdmaenablercreate" => Some(Self::WdfDmaEnablerCreate),
            "wdfdmaenablercalculatemaximumtransfersize" => {
                Some(Self::WdfDmaEnablerCalculateMaximumTransferSize)
            }
            "wdfdmatransactioncreate" => Some(Self::WdfDmaTransactionCreate),
            "wdfdmatransactioninitialize" => Some(Self::WdfDmaTransactionInitialize),
            "wdfdmatransactionexecute" => Some(Self::WdfDmaTransactionExecute),
            "wdfdmatransactionrelease" => Some(Self::WdfDmaTransactionRelease),
            "wdfdmatransactioncancel" => Some(Self::WdfDmaTransactionCancel),
            "wdfusbtargetdevicecreate" => Some(Self::WdfUsbTargetDeviceCreate),
            "wdfusbtargetdevicegetinformation" => Some(Self::WdfUsbTargetDeviceGetInformation),
            "wdfusbinterfacegetconfiguredpipe" => Some(Self::WdfUsbInterfaceGetConfiguredPipe),
            "wdfusbtargetpipereadpipe" => Some(Self::WdfUsbTargetPipeReadPipe),
            "wdfusbtargetpipewritepipe" => Some(Self::WdfUsbTargetPipeWritePipe),
            "wdfusbtargetpipeabortpipe" => Some(Self::WdfUsbTargetPipeAbortPipe),
            "wdfusbtargetpiperesetpipe" => Some(Self::WdfUsbTargetPipeResetPipe),
            "wdfusbtargetpipegettype" => Some(Self::WdfUsbTargetPipeGetType),
            "wdfregistryopenkey" => Some(Self::WdfRegistryOpenKey),
            "wdfregistrycreatekey" => Some(Self::WdfRegistryCreateKey),
            "wdfregistryclose" => Some(Self::WdfRegistryClose),
            "wdfregistryqueryvalue" => Some(Self::WdfRegistryQueryValue),
            "wdfregistryassignvalue" | "wdfregistrysetvalue" => Some(Self::WdfRegistryAssignValue),
            "wdfregistrydeletevalue" => Some(Self::WdfRegistryDeleteValue),
            "wdfchildlistcreate" => Some(Self::WdfChildListCreate),
            "wdfchildlistgetfirst" => Some(Self::WdfChildListGetFirst),
            "wdfchildlistgetnext" => Some(Self::WdfChildListGetNext),
            "wdfchildlistgetchildcount" => Some(Self::WdfChildListGetChildCount),
            "wdfcmresourcelistcreate" => Some(Self::WdfCmResourceListCreate),
            "wdfcmresourcelistgetdescriptor" => Some(Self::WdfCmResourceListGetDescriptor),
            "wdfcmresourcelistgetcount" => Some(Self::WdfCmResourceListGetCount),
            "wdfmemorycopy" => Some(Self::WdfMemoryCopy),
            "wdfmemoryassign" => Some(Self::WdfMemoryAssign),
            "wdfrequestcreatefromirp" => Some(Self::WdfRequestCreateFromIrp),
            "wdfrequestimpersonate" => Some(Self::WdfRequestImpersonate),
            "wdfrequeststopimpersonating" => Some(Self::WdfRequestStopImpersonating),
            "wdfrequestwdmgetirp" => Some(Self::WdfRequestWdmGetIrp),
            "wdfrequestsetinformation" => Some(Self::WdfRequestSetInformation),
            "wdfrequestforwardtoparentdeviceioqueue" => {
                Some(Self::WdfRequestForwardToParentDeviceIoQueue)
            }
            "wdfobjectreference" => Some(Self::WdfObjectReference),
            "wdfobjectdereference" => Some(Self::WdfObjectDereference),
            "wdfcontroldeviceinitallocate" => Some(Self::WdfControlDeviceInitAllocate),
            "wdfcontrolfinishinitializing" => Some(Self::WdfControlFinishInitializing),
            _ => None,
        }
    }

    /// The stdcall argument byte count popped by the x86 host-thunk
    /// dispatcher after the shim returns.
    pub(crate) fn x86_arg_bytes(self) -> u64 {
        match self {
            Self::DbgPrint => 4,
            Self::IoCreateDevice => 28,
            Self::IoDeleteDevice => 4,
            Self::IoCreateSymbolicLink | Self::IoDeleteSymbolicLink => 8,
            Self::IoAllocateIrp => 8,
            Self::IoFreeIrp => 4,
            Self::RtlInitUnicodeString => 8,
            Self::IofCompleteRequest | Self::IoCompleteRequest => 8,
            Self::ExAllocatePoolWithTag => 12,
            Self::ExFreePoolWithTag => 8,
            Self::ExAllocatePool => 8,
            Self::ExFreePool => 4,
            Self::KeGetCurrentIrql
            | Self::KeQuerySystemTime
            | Self::PsGetCurrentProcessId
            | Self::PsGetCurrentThreadId => 0,
            Self::KfRaiseIrql | Self::KfLowerIrql => 4,
            Self::KeAcquireSpinLockRaiseToDpc => 4,
            Self::KeReleaseSpinLock => 8,
            Self::KeInitializeDpc => 12,
            Self::KeInsertQueueDpc => 12,
            Self::KeRemoveQueueDpc => 4,
            Self::KeInitializeEvent => 12,
            Self::KeSetEvent => 12,
            Self::KeResetEvent | Self::KeReadStateEvent => 4,
            Self::KeWaitForSingleObject => 16,
            Self::IoAllocateMdl => 20,
            Self::MmProbeAndLockPages => 12,
            Self::MmUnlockPages | Self::IoFreeMdl | Self::MmGetMdlByteCount => 4,
            Self::ZwOpenKey => 12,
            Self::ZwQueryValueKey => 24,
            Self::ZwClose => 4,
            Self::ExInitializeNPagedLookasideList | Self::ExInitializePagedLookasideList => 28,
            Self::ExAllocateFromNPagedLookasideList | Self::ExAllocateFromPagedLookasideList => 4,
            Self::ExFreeToNPagedLookasideList | Self::ExFreeToPagedLookasideList => 8,
            Self::PsCreateSystemThread => 20,
            Self::PsTerminateSystemThread
            | Self::IoConnectInterruptEx
            | Self::IoDisconnectInterrupt => 4,
            Self::IoConnectInterrupt => 44,
            Self::EtwRegister => 16,
            Self::EtwUnregister => 4,
            Self::EtwWrite => 16,
            Self::NtAlpcConnectPort => 28,
            Self::KeQueryInterruptTime | Self::IslandSafepoint => 0,
            Self::IrpDispatch => 8,
            Self::WdfDriverCreate => 20,
            Self::WdfDeviceInitSetDeviceType | Self::WdfDeviceInitSetIoType => 8,
            Self::WdfDeviceInitAssignName => 8,
            Self::WdfDeviceCreate => 12,
            Self::WdfIoQueueCreate => 16,
            Self::WdfRequestCreate => 12,
            Self::WdfRequestFormatRequestForIoctl => 32,
            Self::WdfRequestRetrieveInputBuffer | Self::WdfRequestRetrieveOutputBuffer => 16,
            Self::WdfRequestComplete => 8,
            Self::WdfRequestCompleteWithInformation => 12,
            Self::WdfDeviceWdmGetDeviceObject => 4,
            Self::WdfObjectGetTypedContext => 8,
            Self::WdfObjectDelete => 4,
            Self::WdfWaitLockCreate => 8,
            Self::WdfWaitLockAcquire => 8,
            Self::WdfWaitLockRelease => 4,
            Self::WdfObjectAllocateContext => 12,
            Self::WdfDeviceGetIoTarget => 4,
            Self::WdfIoTargetCreate => 12,
            Self::WdfIoTargetSendIoctlSynchronously => 28,
            Self::WdfIoTargetFormatRequestForIoctl => 28,
            Self::WdfRequestSend => 12,
            Self::WdfRequestCancelQueuedRequest => 4,
            Self::WdfIoQueueRetrieveNextRequest | Self::WdfIoQueueRetrieveFoundRequest => 12,
            Self::WdfIoQueueStop | Self::WdfIoQueueDrain | Self::WdfIoQueuePurge => 12,
            Self::WdfIoQueueStopSynchronously
            | Self::WdfIoQueueDrainSynchronously
            | Self::WdfIoQueuePurgeSynchronously
            | Self::WdfIoQueueStart => 4,
            Self::WdfEvtIoReadDispatch
            | Self::WdfEvtIoWriteDispatch
            | Self::WdfEvtIoDeviceControlDispatch
            | Self::WdfEvtIoCleanupDispatch
            | Self::WdfEvtIoCloseDispatch
            | Self::WdfEvtPnpDispatch
            | Self::WdfEvtPowerDispatch => 8,
            Self::WdfDeviceInitSetPnpPowerEventCallbacks
            | Self::WdfDeviceInitSetFileObjectConfig => 8,
            Self::WdfMemoryCreate => 24,
            Self::WdfMemoryCreatePreallocated => 16,
            Self::WdfMemoryGetBuffer => 8,
            Self::WdfStringCreate => 12,
            Self::WdfStringGetUnicodeString => 8,
            Self::WdfDeviceEnqueueRequest => 8,
            Self::WdfPdoInitAllocate => 4,
            Self::WdfPdoInitAssignDeviceID
            | Self::WdfPdoInitAssignInstanceID
            | Self::WdfPdoInitAddHardwareID
            | Self::WdfPdoInitAddCompatibleID => 8,
            Self::WdfSpinLockCreate => 8,
            Self::WdfSpinLockAcquire | Self::WdfSpinLockRelease => 4,
            Self::WdfTimerCreate | Self::WdfWorkItemCreate => 12,
            Self::WdfTimerStart | Self::WdfTimerStop => 8,
            Self::WdfWorkItemEnqueue | Self::WdfWorkItemFlush => 4,
            Self::WdfRequestFormatRequestForRead | Self::WdfRequestFormatRequestForWrite => 20,
            Self::WdfRequestGetStatus
            | Self::WdfRequestIsCanceled
            | Self::WdfRequestUnmarkCancelable
            | Self::WdfDeviceResumeIdle => 4,
            Self::WdfRequestMarkCancelable
            | Self::WdfRequestForwardToIoQueue
            | Self::WdfDeviceStopIdle
            | Self::WdfDeviceInitSetPowerPolicyOwnership => 8,
            Self::WdfCollectionCreate
            | Self::WdfCmResourceListCreate
            | Self::WdfMemoryCopy
            | Self::WdfMemoryAssign
            | Self::WdfRequestCreateFromIrp
            | Self::WdfRequestForwardToParentDeviceIoQueue
            | Self::WdfDmaTransactionCreate
            | Self::WdfInterruptSynchronize => 12,
            Self::WdfCollectionAdd
            | Self::WdfCollectionRemove
            | Self::WdfCollectionGetItem
            | Self::WdfCollectionContains2
            | Self::WdfMemoryCreateFromLookaside
            | Self::WdfDmaTransactionExecute
            | Self::WdfUsbTargetDeviceGetInformation
            | Self::WdfRegistryDeleteValue
            | Self::WdfChildListGetFirst
            | Self::WdfChildListGetNext
            | Self::WdfCmResourceListGetDescriptor
            | Self::WdfRequestImpersonate
            | Self::WdfRequestSetInformation
            | Self::WdfControlDeviceInitAllocate => 8,
            Self::WdfCollectionRemoveAll
            | Self::WdfCollectionGetCount
            | Self::WdfInterruptQueueDpcForIsr
            | Self::WdfInterruptAcquireLock
            | Self::WdfInterruptReleaseLock
            | Self::WdfInterruptDisable
            | Self::WdfInterruptEnable
            | Self::WdfDmaEnablerCalculateMaximumTransferSize
            | Self::WdfDmaTransactionRelease
            | Self::WdfDmaTransactionCancel
            | Self::WdfUsbTargetPipeAbortPipe
            | Self::WdfUsbTargetPipeResetPipe
            | Self::WdfUsbTargetPipeGetType
            | Self::WdfRegistryClose
            | Self::WdfChildListGetChildCount
            | Self::WdfEvtChildListScanDispatch
            | Self::WdfCmResourceListGetCount
            | Self::WdfRequestStopImpersonating
            | Self::WdfRequestWdmGetIrp
            | Self::WdfObjectReference
            | Self::WdfObjectDereference
            | Self::WdfControlFinishInitializing => 4,
            Self::WdfInterruptCreate
            | Self::WdfDmaEnablerCreate
            | Self::WdfUsbTargetDeviceCreate
            | Self::WdfUsbInterfaceGetConfiguredPipe
            | Self::WdfUsbTargetPipeReadPipe
            | Self::WdfUsbTargetPipeWritePipe
            | Self::WdfRegistryOpenKey
            | Self::WdfRegistryCreateKey
            | Self::WdfChildListCreate => 16,
            Self::WdfLookasideListCreate
            | Self::WdfDmaTransactionInitialize
            | Self::WdfRegistryAssignValue => 20,
            Self::WdfRegistryQueryValue => 24,
        }
    }
}

impl DriverIsland {
    /// Invoke one island shim directly from a test, with arguments placed in
    /// the guest ABI locations the shim reads.  This exercises the same shim
    /// path as guest code without needing a hand-assembled caller for every
    /// operation.
    #[cfg(test)]
    pub(crate) fn call_shim_for_test(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        function: DriverShim,
        args: &[u64],
    ) -> AppResult<u64> {
        let inner = self.inner.clone();
        let _active = ActiveIsland::install(inner.clone());
        let arch = inner.borrow().arch;
        let mut cpu = CpuState::new(arch);
        let rsp = STACK_BASE + STACK_SIZE - 0x300;
        cpu.set(Register::Rsp, rsp);
        match arch {
            GuestArch::X64 => {
                let registers = [Register::Rcx, Register::Rdx, Register::R8, Register::R9];
                for (index, value) in args.iter().enumerate() {
                    if let Some(register) = registers.get(index) {
                        cpu.set(*register, *value);
                    } else {
                        memory.write_u64(rsp + 0x20 + (index as u64 - 4) * 8, *value);
                    }
                }
            }
            GuestArch::X86 => {
                for (index, value) in args.iter().enumerate() {
                    memory.write_u32(rsp + index as u64 * 4, *value as u32);
                }
            }
        }
        dispatch_shim(runtime, &mut cpu, memory, function)?;
        Ok(cpu.get(Register::Rax))
    }
}

impl IslandState {
    pub(crate) fn handle_shim(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        function: DriverShim,
    ) -> AppResult<Option<PendingGuestCall>> {
        match function {
            DriverShim::DbgPrint => self.dbg_print(runtime, state, memory)?,
            DriverShim::IoCreateDevice => self.io_create_device(state, memory)?,
            DriverShim::IoDeleteDevice => self.io_delete_device(state, memory)?,
            DriverShim::IoCreateSymbolicLink => self.io_create_symbolic_link(state, memory)?,
            DriverShim::IoDeleteSymbolicLink => self.io_delete_symbolic_link(state, memory)?,
            DriverShim::IoAllocateIrp => self.io_allocate_irp(state, memory)?,
            DriverShim::IoFreeIrp => self.io_free_irp(state, memory)?,
            DriverShim::RtlInitUnicodeString => self.rtl_init_unicode_string(state, memory)?,
            DriverShim::IofCompleteRequest | DriverShim::IoCompleteRequest => {
                self.io_complete_request(state, memory)?
            }
            DriverShim::ExAllocatePoolWithTag => self.ex_allocate_pool(state, memory)?,
            DriverShim::ExFreePoolWithTag => self.ex_free_pool(state, memory)?,
            DriverShim::ExAllocatePool => self.ex_allocate_pool_untagged(state, memory)?,
            DriverShim::ExFreePool => self.ex_free_pool_untagged(state, memory)?,
            DriverShim::KeGetCurrentIrql => self.ke_get_current_irql(state),
            DriverShim::KfRaiseIrql => self.kf_raise_irql(state, memory)?,
            DriverShim::KfLowerIrql => return self.kf_lower_irql(state, memory),
            DriverShim::KeAcquireSpinLockRaiseToDpc => self.ke_acquire_spin_lock(state, memory)?,
            DriverShim::KeReleaseSpinLock => self.ke_release_spin_lock(state, memory)?,
            DriverShim::KeInitializeDpc => self.ke_initialize_dpc(state, memory)?,
            DriverShim::KeInsertQueueDpc => return self.ke_insert_queue_dpc(state, memory),
            DriverShim::KeRemoveQueueDpc => self.ke_remove_queue_dpc(state, memory)?,
            DriverShim::KeInitializeEvent => self.ke_initialize_event(state, memory)?,
            DriverShim::KeSetEvent => self.ke_set_event(state, memory)?,
            DriverShim::KeResetEvent => self.ke_reset_event(state, memory)?,
            DriverShim::KeReadStateEvent => self.ke_read_state_event(state, memory)?,
            DriverShim::KeWaitForSingleObject => {
                self.ke_wait_for_single_object(runtime, state, memory)?
            }
            DriverShim::KeQuerySystemTime => self.ke_query_system_time(state, memory)?,
            DriverShim::KeQueryInterruptTime => self.ke_query_interrupt_time(state),
            DriverShim::IslandSafepoint => {
                set_status(state, STATUS_SUCCESS);
                self.maybe_preempt(runtime);
            }
            DriverShim::IoAllocateMdl => self.io_allocate_mdl(state, memory)?,
            DriverShim::MmProbeAndLockPages => {
                self.mm_probe_and_lock_pages(runtime, state, memory)?
            }
            DriverShim::MmUnlockPages => self.mm_unlock_pages(state, memory)?,
            DriverShim::IoFreeMdl => self.io_free_mdl(state, memory)?,
            DriverShim::MmGetMdlByteCount => self.mm_get_mdl_byte_count(state, memory)?,
            DriverShim::PsGetCurrentProcessId => self.ps_get_current_process_id(state),
            DriverShim::PsGetCurrentThreadId => self.ps_get_current_thread_id(state),
            DriverShim::ZwOpenKey => self.zw_open_key(runtime, state, memory)?,
            DriverShim::ZwQueryValueKey => self.zw_query_value_key(runtime, state, memory)?,
            DriverShim::ZwClose => self.zw_close(state, memory)?,
            DriverShim::ExInitializeNPagedLookasideList => {
                self.ex_initialize_lookaside(state, memory, NON_PAGED_POOL)?
            }
            DriverShim::ExAllocateFromNPagedLookasideList => {
                self.ex_allocate_from_lookaside(state, memory, NON_PAGED_POOL)?
            }
            DriverShim::ExFreeToNPagedLookasideList => {
                self.ex_free_to_lookaside(state, memory, NON_PAGED_POOL)?
            }
            DriverShim::ExInitializePagedLookasideList => {
                self.ex_initialize_lookaside(state, memory, PAGED_POOL)?
            }
            DriverShim::ExAllocateFromPagedLookasideList => {
                self.ex_allocate_from_lookaside(state, memory, PAGED_POOL)?
            }
            DriverShim::ExFreeToPagedLookasideList => {
                self.ex_free_to_lookaside(state, memory, PAGED_POOL)?
            }
            DriverShim::PsCreateSystemThread => {
                self.ps_create_system_thread(runtime, state, memory)?
            }
            DriverShim::PsTerminateSystemThread => {
                self.ps_terminate_system_thread(state, memory)?
            }
            DriverShim::IoConnectInterrupt => self.io_connect_interrupt(runtime, state, memory)?,
            DriverShim::IoConnectInterruptEx => {
                self.io_connect_interrupt_ex(runtime, state, memory)?
            }
            DriverShim::IoDisconnectInterrupt => self.io_disconnect_interrupt(state, memory)?,
            DriverShim::EtwRegister => self.etw_register(state, memory)?,
            DriverShim::EtwUnregister => self.etw_unregister(state, memory)?,
            DriverShim::EtwWrite => self.etw_write(state, memory)?,
            DriverShim::NtAlpcConnectPort => self.nt_alpc_connect_port(state, memory)?,
            DriverShim::IrpDispatch => {
                set_status(state, crate::casak::io::STATUS_INVALID_DEVICE_REQUEST);
            }
            DriverShim::WdfDriverCreate => {
                return self.wdf_driver_create(runtime, state, memory);
            }
            DriverShim::WdfDeviceInitSetDeviceType => {
                self.wdf_device_init_set_device_type(state, memory)?
            }
            DriverShim::WdfDeviceInitSetIoType => {
                self.wdf_device_init_set_io_type(state, memory)?
            }
            DriverShim::WdfDeviceInitAssignName => {
                self.wdf_device_init_assign_name(state, memory)?
            }
            DriverShim::WdfDeviceCreate => self.wdf_device_create(state, memory)?,
            DriverShim::WdfIoQueueCreate => self.wdf_io_queue_create(state, memory)?,
            DriverShim::WdfRequestCreate => self.wdf_request_create(state, memory)?,
            DriverShim::WdfRequestFormatRequestForIoctl => {
                self.wdf_request_format_for_ioctl(state, memory)?
            }
            DriverShim::WdfRequestRetrieveInputBuffer => {
                self.wdf_request_retrieve_buffer(state, memory, true)?
            }
            DriverShim::WdfRequestRetrieveOutputBuffer => {
                self.wdf_request_retrieve_buffer(state, memory, false)?
            }
            DriverShim::WdfRequestComplete => self.wdf_request_complete(state, memory, None)?,
            DriverShim::WdfRequestCompleteWithInformation => {
                let information = guest_arg(state, memory, 2)? as usize;
                self.wdf_request_complete(state, memory, Some(information))?
            }
            DriverShim::WdfDeviceWdmGetDeviceObject => {
                self.wdf_device_wdm_get_device_object(state, memory)?
            }
            DriverShim::WdfObjectGetTypedContext => {
                self.wdf_object_get_typed_context(state, memory)?
            }
            DriverShim::WdfObjectDelete => return self.wdf_object_delete(state, memory),
            DriverShim::WdfWaitLockCreate => self.wdf_wait_lock_create(state, memory)?,
            DriverShim::WdfWaitLockAcquire => self.wdf_wait_lock_acquire(state, memory)?,
            DriverShim::WdfWaitLockRelease => self.wdf_wait_lock_release(state, memory)?,
            DriverShim::WdfObjectAllocateContext => {
                self.wdf_object_allocate_context(state, memory)?
            }
            DriverShim::WdfDeviceGetIoTarget => self.wdf_device_get_iotarget(state, memory)?,
            DriverShim::WdfIoTargetCreate => self.wdf_iotarget_create(state, memory)?,
            DriverShim::WdfIoTargetSendIoctlSynchronously => {
                return self.wdf_iotarget_send_ioctl(runtime, state, memory);
            }
            DriverShim::WdfIoTargetFormatRequestForIoctl => {
                self.wdf_iotarget_format_request(state, memory)?
            }
            DriverShim::WdfRequestSend => return self.wdf_request_send(runtime, state, memory),
            DriverShim::WdfRequestCancelQueuedRequest => {
                return self.wdf_request_cancel_queued(state, memory);
            }
            DriverShim::WdfIoQueueRetrieveNextRequest => {
                self.wdf_queue_retrieve(state, memory, false)?
            }
            DriverShim::WdfIoQueueRetrieveFoundRequest => {
                self.wdf_queue_retrieve(state, memory, true)?
            }
            DriverShim::WdfIoQueueStop => {
                return self.wdf_queue_stop(state, memory, false, false);
            }
            DriverShim::WdfIoQueueStopSynchronously => {
                return self.wdf_queue_stop(state, memory, false, true);
            }
            DriverShim::WdfIoQueueDrain => {
                return self.wdf_queue_stop(state, memory, true, false);
            }
            DriverShim::WdfIoQueueDrainSynchronously => {
                return self.wdf_queue_stop(state, memory, true, true);
            }
            DriverShim::WdfIoQueuePurge | DriverShim::WdfIoQueuePurgeSynchronously => {
                return self.wdf_queue_purge(state, memory);
            }
            DriverShim::WdfIoQueueStart => return self.wdf_queue_start(state, memory),
            DriverShim::WdfEvtIoReadDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Read, state, memory);
            }
            DriverShim::WdfEvtIoWriteDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Write, state, memory);
            }
            DriverShim::WdfEvtIoDeviceControlDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::DeviceControl, state, memory);
            }
            DriverShim::WdfEvtIoCleanupDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Cleanup, state, memory);
            }
            DriverShim::WdfEvtIoCloseDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Close, state, memory);
            }
            DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks => {
                self.wdf_device_init_set_pnp_power_callbacks(state, memory)?
            }
            DriverShim::WdfDeviceInitSetFileObjectConfig => {
                self.wdf_device_init_set_file_object_config(state, memory)?
            }
            DriverShim::WdfMemoryCreate => self.wdf_memory_create(state, memory, false)?,
            DriverShim::WdfMemoryCreatePreallocated => {
                self.wdf_memory_create(state, memory, true)?
            }
            DriverShim::WdfMemoryGetBuffer => self.wdf_memory_get_buffer(state, memory)?,
            DriverShim::WdfStringCreate => self.wdf_string_create(state, memory)?,
            DriverShim::WdfStringGetUnicodeString => {
                self.wdf_string_get_unicode_string(state, memory)?
            }
            DriverShim::WdfDeviceEnqueueRequest => {
                return self.wdf_device_enqueue_request(state, memory);
            }
            DriverShim::WdfPdoInitAllocate => self.wdf_pdo_init_allocate(state, memory)?,
            DriverShim::WdfPdoInitAssignDeviceID => {
                self.wdf_pdo_init_set_id(state, memory, false)?
            }
            DriverShim::WdfPdoInitAssignInstanceID => {
                self.wdf_pdo_init_set_id(state, memory, true)?
            }
            DriverShim::WdfPdoInitAddHardwareID => {
                self.wdf_pdo_init_add_id(state, memory, false)?
            }
            DriverShim::WdfPdoInitAddCompatibleID => {
                self.wdf_pdo_init_add_id(state, memory, true)?
            }
            DriverShim::WdfSpinLockCreate => self.wdf_spin_lock_create(state, memory)?,
            DriverShim::WdfSpinLockAcquire => self.wdf_spin_lock_acquire(state, memory)?,
            DriverShim::WdfSpinLockRelease => self.wdf_spin_lock_release(state, memory)?,
            DriverShim::WdfTimerCreate => self.wdf_timer_create(state, memory)?,
            DriverShim::WdfTimerStart => return self.wdf_timer_start(state, memory),
            DriverShim::WdfTimerStop => self.wdf_timer_stop(state, memory)?,
            DriverShim::WdfWorkItemCreate => self.wdf_work_item_create(state, memory)?,
            DriverShim::WdfWorkItemEnqueue => {
                return self.wdf_work_item_enqueue(state, memory);
            }
            DriverShim::WdfWorkItemFlush => self.wdf_work_item_flush(state, memory)?,
            DriverShim::WdfRequestFormatRequestForRead => {
                self.wdf_request_format_for_read_write(state, memory, true)?
            }
            DriverShim::WdfRequestFormatRequestForWrite => {
                self.wdf_request_format_for_read_write(state, memory, false)?
            }
            DriverShim::WdfRequestGetStatus => self.wdf_request_get_status(state, memory)?,
            DriverShim::WdfRequestIsCanceled => self.wdf_request_is_canceled(state, memory)?,
            DriverShim::WdfRequestMarkCancelable => {
                self.wdf_request_mark_cancelable(state, memory)?
            }
            DriverShim::WdfRequestUnmarkCancelable => {
                self.wdf_request_unmark_cancelable(state, memory)?
            }
            DriverShim::WdfDeviceStopIdle => {
                return self.wdf_device_stop_idle(state, memory);
            }
            DriverShim::WdfDeviceResumeIdle => {
                return self.wdf_device_resume_idle(state, memory);
            }
            DriverShim::WdfRequestForwardToIoQueue => {
                return self.wdf_request_forward_to_io_queue(state, memory);
            }
            DriverShim::WdfDeviceInitSetPowerPolicyOwnership => {
                self.wdf_device_init_set_power_policy_ownership(state, memory)?
            }
            DriverShim::WdfCollectionCreate => self.wdf_collection_create(state, memory)?,
            DriverShim::WdfCollectionAdd => self.wdf_collection_add(state, memory)?,
            DriverShim::WdfCollectionRemove => self.wdf_collection_remove(state, memory)?,
            DriverShim::WdfCollectionRemoveAll => self.wdf_collection_remove_all(state, memory)?,
            DriverShim::WdfCollectionGetItem => self.wdf_collection_get_item(state, memory)?,
            DriverShim::WdfCollectionGetCount => self.wdf_collection_get_count(state, memory)?,
            DriverShim::WdfCollectionContains2 => self.wdf_collection_contains(state, memory)?,
            DriverShim::WdfLookasideListCreate => self.wdf_lookaside_list_create(state, memory)?,
            DriverShim::WdfMemoryCreateFromLookaside => {
                self.wdf_memory_create_from_lookaside(state, memory)?
            }
            DriverShim::WdfInterruptCreate => self.wdf_interrupt_create(state, memory)?,
            DriverShim::WdfInterruptQueueDpcForIsr => {
                return self.wdf_interrupt_queue_dpc(state, memory);
            }
            DriverShim::WdfInterruptAcquireLock => {
                self.wdf_interrupt_acquire_lock(state, memory)?
            }
            DriverShim::WdfInterruptReleaseLock => {
                self.wdf_interrupt_release_lock(state, memory)?
            }
            DriverShim::WdfInterruptSynchronize => {
                return self.wdf_interrupt_synchronize(state, memory);
            }
            DriverShim::WdfInterruptDisable => {
                self.wdf_interrupt_set_enabled(state, memory, false)?
            }
            DriverShim::WdfInterruptEnable => {
                self.wdf_interrupt_set_enabled(state, memory, true)?
            }
            DriverShim::WdfDmaEnablerCreate => self.wdf_dma_enabler_create(state, memory)?,
            DriverShim::WdfDmaEnablerCalculateMaximumTransferSize => {
                self.wdf_dma_max_transfer_size(state, memory)?
            }
            DriverShim::WdfDmaTransactionCreate => {
                self.wdf_dma_transaction_create(state, memory)?
            }
            DriverShim::WdfDmaTransactionInitialize => {
                self.wdf_dma_transaction_initialize(state, memory)?
            }
            DriverShim::WdfDmaTransactionExecute => {
                return self.wdf_dma_transaction_execute(state, memory);
            }
            DriverShim::WdfDmaTransactionRelease => {
                self.wdf_dma_transaction_release(state, memory)?
            }
            DriverShim::WdfDmaTransactionCancel => {
                self.wdf_dma_transaction_cancel(state, memory)?
            }
            DriverShim::WdfUsbTargetDeviceCreate => {
                self.wdf_usb_target_device_create(state, memory)?
            }
            DriverShim::WdfUsbTargetDeviceGetInformation => {
                self.wdf_usb_target_get_information(state, memory)?
            }
            DriverShim::WdfUsbInterfaceGetConfiguredPipe => {
                self.wdf_usb_get_configured_pipe(state, memory)?
            }
            DriverShim::WdfUsbTargetPipeReadPipe => {
                return self.wdf_usb_pipe_transfer(state, memory, true);
            }
            DriverShim::WdfUsbTargetPipeWritePipe => {
                return self.wdf_usb_pipe_transfer(state, memory, false);
            }
            DriverShim::WdfUsbTargetPipeAbortPipe => self.wdf_usb_pipe_abort(state, memory)?,
            DriverShim::WdfUsbTargetPipeResetPipe => self.wdf_usb_pipe_reset(state, memory)?,
            DriverShim::WdfUsbTargetPipeGetType => self.wdf_usb_pipe_get_type(state, memory)?,
            DriverShim::WdfRegistryOpenKey => self.wdf_registry_open_key(runtime, state, memory)?,
            DriverShim::WdfRegistryCreateKey => {
                self.wdf_registry_create_key(runtime, state, memory)?
            }
            DriverShim::WdfRegistryClose => self.wdf_registry_close(state, memory)?,
            DriverShim::WdfRegistryQueryValue => {
                self.wdf_registry_query_value(runtime, state, memory)?
            }
            DriverShim::WdfRegistryAssignValue => {
                self.wdf_registry_assign_value(runtime, state, memory)?
            }
            DriverShim::WdfRegistryDeleteValue => {
                self.wdf_registry_delete_value(runtime, state, memory)?
            }
            DriverShim::WdfChildListCreate => self.wdf_child_list_create(state, memory)?,
            DriverShim::WdfChildListGetFirst => self.wdf_child_list_get_first(state, memory)?,
            DriverShim::WdfChildListGetNext => self.wdf_child_list_get_next(state, memory)?,
            DriverShim::WdfChildListGetChildCount => {
                self.wdf_child_list_get_count(state, memory)?
            }
            DriverShim::WdfEvtChildListScanDispatch => {
                return self.wdf_child_list_scan(state, memory);
            }
            DriverShim::WdfCmResourceListCreate => {
                self.wdf_cm_resource_list_create(state, memory)?
            }
            DriverShim::WdfCmResourceListGetDescriptor => {
                self.wdf_cm_resource_list_get_descriptor(state, memory)?
            }
            DriverShim::WdfCmResourceListGetCount => {
                self.wdf_cm_resource_list_get_count(state, memory)?
            }
            DriverShim::WdfMemoryCopy => self.wdf_memory_copy(state, memory)?,
            DriverShim::WdfMemoryAssign => self.wdf_memory_assign(state, memory)?,
            DriverShim::WdfRequestCreateFromIrp => {
                self.wdf_request_create_from_irp(state, memory)?
            }
            DriverShim::WdfRequestImpersonate => self.wdf_request_impersonate(state, memory)?,
            DriverShim::WdfRequestStopImpersonating => {
                self.wdf_request_stop_impersonating(state, memory)?
            }
            DriverShim::WdfRequestWdmGetIrp => self.wdf_request_wdm_get_irp(state, memory)?,
            DriverShim::WdfRequestSetInformation => {
                self.wdf_request_set_information(state, memory)?
            }
            DriverShim::WdfRequestForwardToParentDeviceIoQueue => {
                return self.wdf_request_forward_to_parent(state, memory);
            }
            DriverShim::WdfObjectReference => self.wdf_object_reference(state, memory)?,
            DriverShim::WdfObjectDereference => return self.wdf_object_dereference(state, memory),
            DriverShim::WdfControlDeviceInitAllocate => {
                self.wdf_control_device_init_allocate(state, memory)?
            }
            DriverShim::WdfControlFinishInitializing => {
                self.wdf_control_finish_initializing(state, memory)?
            }
            DriverShim::WdfEvtPnpDispatch => return self.wdf_pnp_dispatch(state, memory),
            DriverShim::WdfEvtPowerDispatch => return self.wdf_power_dispatch(state, memory),
        }
        Ok(None)
    }
}

/// Dispatches one island shim from the runtime's `HostThunk` match arm.
pub(crate) fn dispatch_shim(
    runtime: &mut PeHostRuntime,
    state: &mut CpuState,
    memory: &mut MemoryImage,
    function: DriverShim,
) -> AppResult<()> {
    let island = ACTIVE_ISLAND
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("driver island shim {function:?} invoked with no active island"),
            )
        })?;
    let mut pending = {
        let mut island_state = island.borrow_mut();
        let pending = island_state.handle_shim(runtime, state, memory, function)?;
        island_state.maybe_preempt(runtime);
        pending
    };
    while let Some(call) = pending {
        let arch = island.borrow().arch;
        let mut cpu = CpuState::new(arch);
        // Leave the top frame for the context that invoked the shim: a KMDF
        // callback runs while DriverEntry (or a MajorFunction handler) is still
        // live on the same guest stack.
        cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x800);
        let result =
            runtime.execute_guest_callback(&mut cpu, memory, call.entry, &call.args, call.label);
        let status = match result {
            Ok(value) => value as u32 as i32,
            Err(_) => STATUS_INVALID_PARAMETER,
        };
        pending = {
            let mut island_state = island.borrow_mut();
            island_state.finish_pending(state, memory, call.purpose, status)?
        };
    }
    Ok(())
}
