//! Host-thunk enum catalog (moved verbatim from `runtime::mod`).

use super::*;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum HostThunk {
    TbsiContextCreate,
    TbsipSubmitCommand,
    TbsipContextClose,
    CreateDXGIFactory1,
    CreateDXGIFactory2,
    DXGIFactoryEnumAdapters,
    DXGIFactoryEnumAdapters1,
    DXGIAdapterGetDesc,
    DXGIAdapterGetDesc1,
    DXGIFactoryCreateSwapChain,
    DXGIFactoryCreateSwapChainForHwnd,
    D3D11CreateDevice,
    D3D11CreateDeviceAndSwapChain,
    D3D12CreateDevice,
    D3D12DeviceCreateCommandQueue,
    D3D12DeviceCreateCommandAllocator,
    D3D12DeviceCreateCommandList,
    D3D12DeviceCheckFeatureSupport,
    D3D12DeviceCreateDescriptorHeap,
    D3D12DeviceCreateRenderTargetView,
    D3D12DeviceCreateFence,
    D3D12CommandQueueExecuteCommandLists,
    D3D12CommandQueueSignal,
    D3D12DescriptorHeapGetCpuHandleForHeapStart,
    D3D12GraphicsCommandListResourceBarrier,
    D3D12GraphicsCommandListClearRenderTargetView,
    D3D12GraphicsCommandListDrawInstanced,
    D3D12GraphicsCommandListClose,
    D3D12CommandListGetDevice,
    D3D12GraphicsCommandListClearState,
    D3D12GraphicsCommandListDrawIndexedInstanced,
    D3D12GraphicsCommandListCopyBufferRegion,
    D3D12GraphicsCommandListCopyTiles,
    D3D12GraphicsCommandListResolveSubresource,
    D3D12GraphicsCommandList1AtomicCopyBufferUINT,
    D3D12GraphicsCommandList1AtomicCopyBufferUINT64,
    D3D12GraphicsCommandList1OMSetDepthBounds,
    D3D12GraphicsCommandList1SetSamplePositions,
    D3D12GraphicsCommandList1ResolveSubresourceRegion,
    D3D12GraphicsCommandList1SetViewInstanceMask,
    D3D12GraphicsCommandList2WriteBufferImmediate,
    D3D12GraphicsCommandList3SetProtectedResourceSession,
    D3D12GraphicsCommandList4BeginRenderPass,
    D3D12GraphicsCommandList4EndRenderPass,
    D3D12GraphicsCommandList4InitializeMetaCommand,
    D3D12GraphicsCommandList4ExecuteMetaCommand,
    D3D12GraphicsCommandList4BuildRaytracingAccelerationStructure,
    D3D12GraphicsCommandList4EmitRaytracingAccelerationStructurePostbuildInfo,
    D3D12GraphicsCommandList4CopyRaytracingAccelerationStructure,
    D3D12GraphicsCommandList4SetPipelineState1,
    D3D12GraphicsCommandList4DispatchRays,
    D3D12GraphicsCommandList5RSSetShadingRate,
    D3D12GraphicsCommandList5RSSetShadingRateImage,
    D3D12GraphicsCommandList6DispatchMesh,
    D3D12GraphicsCommandList7Barrier,
    D3D12GraphicsCommandList8OMSetFrontAndBackStencilRef,
    D3D12GraphicsCommandList9RSSetDepthBias,
    D3D12GraphicsCommandList9IASetIndexBufferStripCutValue,
    /// Reset a command list (ID3D12GraphicsCommandList::Reset, vtable slot 10).
    /// For direct command lists, reuses the allocator and optional initial PSO.
    /// For bundle command lists, resets with a bundle allocator.
    D3D12GraphicsCommandListReset,
    /// Execute a pre-recorded bundle on a parent command list
    /// (ID3D12GraphicsCommandList::ExecuteBundle, vtable slot 27).
    D3D12GraphicsCommandListExecuteBundle,
    D3D12FenceGetCompletedValue,
    D3D11DeviceCreateBuffer,
    D3D11DeviceCreateTexture2D,
    D3D11DeviceCreateShaderResourceView,
    D3D11DeviceCreateRenderTargetView,
    D3D11DeviceCreateDepthStencilView,
    D3D11DeviceCreateBlendState,
    D3D11DeviceCreateDepthStencilState,
    D3D11DeviceCreateRasterizerState,
    D3D11DeviceCreateSamplerState,
    D3D11DeviceCreateInputLayout,
    D3D11DeviceCreateVertexShader,
    D3D11DeviceCreatePixelShader,
    D3D11DeviceCreateComputeShader,
    D3D11DeviceGetImmediateContext,
    D3D11DeviceContextDrawIndexed,
    D3D11DeviceContextDraw,
    D3D11DeviceContextDrawIndexedInstanced,
    D3D11DeviceContextDrawInstanced,
    D3D11DeviceContextVSSetConstantBuffers,
    D3D11DeviceContextPSSetShaderResources,
    D3D11DeviceContextPSSetSamplers,
    D3D11DeviceContextVSSetShader,
    D3D11DeviceContextPSSetShader,
    D3D11DeviceContextCSSetShader,
    D3D11DeviceContextIASetInputLayout,
    D3D11DeviceContextIASetVertexBuffers,
    D3D11DeviceContextIASetIndexBuffer,
    D3D11DeviceContextIASetPrimitiveTopology,
    D3D11DeviceContextOMSetRenderTargets,
    D3D11DeviceContextOMSetBlendState,
    D3D11DeviceContextOMSetDepthStencilState,
    D3D11DeviceContextRSSetState,
    D3D11DeviceContextRSSetViewports,
    D3D11DeviceContextRSSetScissorRects,
    D3D11DeviceContextResolveSubresource,
    D3D11DeviceContextUpdateSubresource,
    // -- D3D11 Device Context gap-fill methods (Phase 3.1) --
    D3D11DeviceContextDrawAuto,
    D3D11DeviceContextClearRenderTargetView,
    D3D11DeviceContextClearDepthStencilView,
    D3D11DeviceContextClearUnorderedAccessViewUint,
    D3D11DeviceContextClearUnorderedAccessViewFloat,
    D3D11DeviceContextClearState,
    D3D11DeviceContextVSSetShaderResources,
    D3D11DeviceContextVSSetSamplers,
    D3D11DeviceContextBegin,
    D3D11DeviceContextEnd,
    D3D11DeviceContextGetData,
    D3D11DeviceContextSetPredication,
    D3D11DeviceContextGSSetShader,
    D3D11DeviceContextGSSetConstantBuffers,
    D3D11DeviceContextGSSetShaderResources,
    D3D11DeviceContextGSSetSamplers,
    D3D11DeviceContextHSSetShader,
    D3D11DeviceContextHSSetConstantBuffers,
    D3D11DeviceContextHSSetShaderResources,
    D3D11DeviceContextHSSetSamplers,
    D3D11DeviceContextDSSetShader,
    D3D11DeviceContextDSSetConstantBuffers,
    D3D11DeviceContextDSSetShaderResources,
    D3D11DeviceContextDSSetSamplers,
    D3D11DeviceContextCSSetShaderResources,
    D3D11DeviceContextCSSetUnorderedAccessViews,
    D3D11DeviceContextCSSetSamplers,
    D3D11DeviceContextCSSetConstantBuffers,
    D3D11DeviceContextCSGetShaderResources,
    D3D11DeviceContextCSGetUnorderedAccessViews,
    D3D11DeviceContextCSGetSamplers,
    D3D11DeviceContextCSGetConstantBuffers,
    D3D11DeviceContextGetPredication,
    D3D11DeviceContextCopySubresourceRegion,
    D3D11DeviceContextCopyResource,
    D3D11DeviceContextCopyStructureCount,
    D3D11DeviceContextMap,
    D3D11DeviceContextUnmap,
    D3D11DeviceContextGenerateMips,
    D3D11DeviceContextSetResourceMinLOD,
    D3D11DeviceContextGetResourceMinLOD,
    D3D11DeviceContextResolveSubresourceFlag,
    D3D11DeviceContextFinishCommandList,
    D3D11DeviceContextFlush,
    D3D11DeviceContextExecuteCommandList,
    DXGISwapChainGetBuffer,
    DXGISwapChainPresent,
    DXGISwapChainResizeBuffers,
    DXGISwapChainSetFullscreenState,
    DXGISwapChainGetFullscreenState,
    DXGISwapChainGetDesc,
    DXGISwapChainResizeTarget,
    DXGISwapChainGetContainingOutput,
    DXGISwapChainGetFrameStatistics,
    DXGISwapChainGetLastPresentCount,
    // -- DXGI Factory methods (Phase 5.5 #2) --
    DXGIFactoryMakeWindowAssociation,
    DXGIFactoryGetWindowAssociation,
    DXGIFactorySetPrivateData,
    DXGIFactorySetPrivateDataInterface,
    DXGIFactoryGetPrivateData,
    DXGIFactoryGetParent,
    DXGIFactoryCreateSoftwareAdapter,
    // -- DXGI Factory gap-fill methods (Phase 3.4) --
    DXGIFactoryIsCurrent,
    DXGIFactoryRegisterStereoStatus,
    DXGIFactoryCreateSwapChainForCoreWindow,
    DXGIFactoryCreateSwapChainForComposition,
    DXGIFactoryRegisterStereoStatusEvent,
    DXGIFactoryUnregisterStereoStatus,
    DXGIFactoryRegisterOcclusionStatus,
    DXGIFactoryRegisterOcclusionStatusEvent,
    DXGIFactoryUnregisterOcclusionStatus,
    DXGIFactoryGetCreationFlags,
    DXGIFactoryEnumAdapterByLuid,
    DXGIFactoryEnumWarpAdapter,
    // -- D3D11 Device query methods (Phase 5.5 #2) --
    D3D11DeviceGetDeviceRemovedReason,
    D3D11DeviceCheckFormatSupport,
    D3D11DeviceCheckMultisampleQualityLevels,
    D3D11DeviceGetFeatureLevel,
    D3D11DeviceGetCreationFlags,
    D3D11DeviceCheckCounterInfo,
    D3D11DeviceCreateDeferredContext,
    D3D11DeferredContextFinishCommandList,
    D3D11DeviceCreateQuery,
    D3D11DeviceCreatePredicate,
    D3D11DeviceCreateCounter,
    // -- D3D11 Device gap-fill methods (Phase 3.1) --
    D3D11DeviceCreateTexture1D,
    D3D11DeviceCreateTexture3D,
    D3D11DeviceCreateUnorderedAccessView,
    D3D11DeviceCreateGeometryShader,
    D3D11DeviceCreateGeometryShaderWithStreamOutput,
    D3D11DeviceCreateHullShader,
    D3D11DeviceCreateDomainShader,
    D3D11DeviceCreateClassLinkage,
    D3D11DeviceCheckCounter,
    D3D11DeviceCheckFeatureSupport,
    D3D11DeviceGetImmediateContext_Base,
    D3D11DeviceCreateDeferredContext1,
    D3D11DeviceGetImmediateContext2,
    D3D11DeviceOpenSharedResource,
    // -- D3D11 DeviceContext gap-fill methods (Phase 3.1) --
    D3D11DeviceContextGetDevice,
    // -- DXGI Adapter methods (Phase 5.5 #2) --
    DXGIAdapterCheckInterfaceSupport,
    DXGIAdapterSetPrivateData,
    DXGIAdapterGetPrivateData,
    DXGIAdapterGetParent,
    DXGIAdapterEnumOutputs,
    XAudio2Create,
    GuestObjectAddRef,
    GuestObjectRelease,
    /// A kernel API shim owned by the driver island (`driver_island.rs`).
    DriverIslandShim {
        function: crate::driver_island::DriverShim,
    },
    UnsupportedMethod {
        name: String,
    },
    XAudio2CreateMasteringVoice,
    XAudio2CreateSourceVoice,
    XAudio2StartEngine,
    XAudio2StopEngine,
    XAudio2SourceVoiceStart,
    XAudio2SourceVoiceStop,
    XAudio2SourceVoiceSubmitSourceBuffer,
    XAudio2SourceVoiceFlushSourceBuffers,
    XAudio2VoiceDestroyVoice,
    // -- XAudio2 voice methods (Phase 4.3) --
    XAudio2VoiceGetVoiceDetails,
    XAudio2VoiceSetOutputVoices,
    XAudio2VoiceSetEffectChain,
    XAudio2VoiceEnableEffect,
    XAudio2VoiceDisableEffect,
    XAudio2VoiceGetEffectState,
    XAudio2VoiceSetEffectParameters,
    XAudio2VoiceGetEffectParameters,
    XAudio2VoiceSetFilterParameters,
    XAudio2VoiceGetFilterParameters,
    XAudio2VoiceSetOutputFilterParameters,
    XAudio2VoiceGetOutputFilterParameters,
    XAudio2VoiceSetVolume,
    XAudio2VoiceGetVolume,
    XAudio2VoiceSetChannelVolumes,
    XAudio2VoiceGetChannelVolumes,
    XAudio2VoiceSetOutputMatrix,
    XAudio2VoiceGetOutputMatrix,
    // -- XAudio2 source voice methods (Phase 4.3) --
    XAudio2SourceVoiceDiscontinuity,
    XAudio2SourceVoiceExitLoop,
    XAudio2SourceVoiceGetState,
    XAudio2SourceVoiceSetFrequencyRatio,
    XAudio2SourceVoiceGetFrequencyRatio,
    XAudio2SourceVoiceSetSourceSampleRate,
    // -- XAudio2 engine methods (Phase 4.3) --
    XAudio2CreateSubmixVoice,
    XAudio2CommitChanges,
    // -- XAudio2 no-op / stub methods (previously unsupported) --
    XAudio2RegisterForCallbacks,
    XAudio2UnregisterForCallbacks,
    XAudio2GetPerformanceData,
    XAudio2SetDebugConfiguration,
    // -- IXAPO vtable thunks (Phase 4.3.1) --
    /// `IXAPO::GetRegistrationProperties` — returns effect registration info.
    XAPO_GetRegistrationProperties,
    /// `IXAPO::LockForProcess` — prepare effect for processing at the given format.
    XAPO_LockForProcess,
    /// `IXAPO::UnlockForProcess` — release processing resources.
    XAPO_UnlockForProcess,
    /// `IXAPO::Process` — process audio through the effect.
    XAPO_Process,
    // -- DirectInput8 (Phase 4.3) --
    DirectInput8Create,
    DirectInput8CreateDevice,
    DirectInput8EnumDevices,
    DirectInputDevice8SetDataFormat,
    DirectInputDevice8SetCooperativeLevel,
    DirectInputDevice8Acquire,
    DirectInputDevice8Unacquire,
    DirectInputDevice8GetDeviceState,
    DirectInputDevice8GetDeviceData,
    DirectInputDevice8EnumObjects,
    DirectInputDevice8GetCapabilities,
    DirectInputDevice8SetProperty,
    DirectInputDevice8Poll,
    DirectInputDevice8UnacquireObj,
    DirectInputDevice8SendForceFeedbackCommand,
    DirectInputDevice8SetForceFeedbackState,
    // -- XInput (Phase 5.2.1) --
    XInputGetState,
    XInputSetState,
    XInputGetCapabilities,
    XInputGetDSoundAudioDeviceGuids,
    XInputGetBatteryInformation,
    XInputGetKeystroke,
    XInputEnable,
    // -- Steam Input API (Phase 5.2.4) --
    SteamAPI_ISteamInput_Init,
    SteamAPI_ISteamInput_Shutdown,
    SteamAPI_ISteamInput_RunFrame,
    SteamAPI_ISteamInput_GetConnectedControllers,
    SteamAPI_ISteamInput_GetActionSetHandle,
    SteamAPI_ISteamInput_GetDigitalActionHandle,
    SteamAPI_ISteamInput_GetAnalogActionHandle,
    SteamAPI_ISteamInput_ActivateActionSet,
    SteamAPI_ISteamInput_GetCurrentActionSet,
    SteamAPI_ISteamInput_GetDigitalActionData,
    SteamAPI_ISteamInput_GetAnalogActionData,
    SteamAPI_ISteamInput_TriggerRepeatedHapticPulse,
    SteamAPI_ISteamInput_GetControllerInputType,
    SteamAPI_ISteamInput_GetMotionData,
    SteamAPI_ISteamInput_ShowBindingPanel,
    SteamAPI_ISteamInput_GetGlyphForActionHandle,
    // -- Steam Networking Sockets (Phase 5.4) --
    SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP,
    SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress,
    SteamAPI_ISteamNetworkingSockets_SendMessageToConnection,
    SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnListenSocket,
    SteamAPI_ISteamNetworkingSockets_CloseConnection,
    SteamAPI_ISteamNetworkingSockets_DestroyListenSocket,
    SteamAPI_ISteamNetworkingSockets_CreateListenSocket,
    SteamAPI_ISteamNetworkingSockets_ConnectBySteamID,
    SteamAPI_ISteamNetworkingSockets_AcceptConnection,
    SteamAPI_ISteamNetworkingSockets_GetConnectionStatus,
    SteamAPI_ISteamNetworkingSockets_GetConnectionName,
    // -- Steam Networking Messages (Phase 5.5) --
    SteamAPI_ISteamNetworkingMessages_SendMessageToUser,
    SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel,
    SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser,
    // -- K1: ISteamUserStats (achievements, stats, leaderboards) --
    SteamAPI_ISteamUserStats_RequestCurrentStats,
    SteamAPI_ISteamUserStats_GetStat,
    SteamAPI_ISteamUserStats_SetStat,
    SteamAPI_ISteamUserStats_GetStatFloat,
    SteamAPI_ISteamUserStats_SetStatFloat,
    SteamAPI_ISteamUserStats_GetAchievement,
    SteamAPI_ISteamUserStats_SetAchievement,
    SteamAPI_ISteamUserStats_ClearAchievement,
    SteamAPI_ISteamUserStats_GetAchievementName,
    SteamAPI_ISteamUserStats_GetNumAchievements,
    SteamAPI_ISteamUserStats_FindOrCreateLeaderboard,
    SteamAPI_ISteamUserStats_UploadLeaderboardScore,
    SteamAPI_ISteamUserStats_DownloadLeaderboardEntries,
    SteamAPI_ISteamUserStats_GetLeaderboardEntryCount,
    SteamAPI_ISteamUserStats_GetLeaderboardName,
    SteamAPI_ISteamUserStats_GetLeaderboardSortMethod,
    SteamAPI_ISteamUserStats_GetLeaderboardDisplayType,
    SteamAPI_ISteamUserStats_AttachLeaderboardUGC,
    // -- K2: ISteamFriends --
    SteamAPI_ISteamFriends_GetPersonaName,
    SteamAPI_ISteamFriends_SetPersonaName,
    SteamAPI_ISteamFriends_GetPersonaState,
    SteamAPI_ISteamFriends_SetPersonaState,
    SteamAPI_ISteamFriends_GetFriendCount,
    SteamAPI_ISteamFriends_GetFriendByIndex,
    SteamAPI_ISteamFriends_GetFriendPersonaName,
    SteamAPI_ISteamFriends_GetFriendPersonaState,
    SteamAPI_ISteamFriends_GetFriendGamePlayed,
    SteamAPI_ISteamFriends_SetFriendPersonaState,
    SteamAPI_ISteamFriends_AddFriend,
    SteamAPI_ISteamFriends_RemoveFriend,
    SteamAPI_ISteamFriends_InviteFriend,
    SteamAPI_ISteamFriends_AcceptInvite,
    SteamAPI_ISteamFriends_DeclineInvite,
    SteamAPI_ISteamFriends_GetInviteCount,
    SteamAPI_ISteamFriends_GetInviteByIndex,
    SteamAPI_ISteamFriends_SendFriendMessage,
    SteamAPI_ISteamFriends_GetFriendMessage,
    SteamAPI_ISteamFriends_GetFriendMessageCount,
    SteamAPI_ISteamFriends_JoinClan,
    SteamAPI_ISteamFriends_LeaveClan,
    SteamAPI_ISteamFriends_GetClanCount,
    SteamAPI_ISteamFriends_GetClanByIndex,
    SteamAPI_ISteamFriends_GetClanName,
    SteamAPI_ISteamFriends_IsClanMember,
    SteamAPI_ISteamFriends_SetRichPresence,
    SteamAPI_ISteamFriends_ClearRichPresence,
    SteamAPI_ISteamFriends_ActivateGameOverlayToWebPage,
    SteamAPI_ISteamFriends_ActivateGameOverlayToFriends,
    SteamAPI_ISteamFriends_ActivateGameOverlay,
    SteamAPI_ISteamFriends_ActivateGameOverlayToUser,
    SteamAPI_ISteamFriends_ActivateGameOverlayToStore,
    SteamAPI_ISteamFriends_ActivateGameOverlayToInviteDialog,
    SteamAPI_ISteamFriends_GetSmallFriendAvatar,
    SteamAPI_ISteamFriends_GetMediumFriendAvatar,
    SteamAPI_ISteamFriends_GetLargeFriendAvatar,
    // -- K3: ISteamMatchmaking (lobbies) --
    SteamAPI_ISteamMatchmaking_CreateLobby,
    SteamAPI_ISteamMatchmaking_JoinLobby,
    SteamAPI_ISteamMatchmaking_LeaveLobby,
    SteamAPI_ISteamMatchmaking_GetLobbyData,
    SteamAPI_ISteamMatchmaking_SetLobbyData,
    SteamAPI_ISteamMatchmaking_GetLobbyMemberCount,
    SteamAPI_ISteamMatchmaking_GetLobbyMemberByIndex,
    SteamAPI_ISteamMatchmaking_GetLobbyMemberData,
    SteamAPI_ISteamMatchmaking_SetLobbyMemberData,
    SteamAPI_ISteamMatchmaking_GetLobbyOwner,
    SteamAPI_ISteamMatchmaking_SetLobbyOwner,
    SteamAPI_ISteamMatchmaking_SetLobbyJoinable,
    SteamAPI_ISteamMatchmaking_SendLobbyChatMessage,
    SteamAPI_ISteamMatchmaking_RequestLobbyList,
    SteamAPI_ISteamMatchmaking_GetLobbyByIndex,
    SteamAPI_ISteamMatchmaking_GetLobbyCount,
    // -- K5: ISteamRemoteStorage (cloud storage) --
    SteamAPI_ISteamRemoteStorage_FileWrite,
    SteamAPI_ISteamRemoteStorage_FileRead,
    SteamAPI_ISteamRemoteStorage_FileDelete,
    SteamAPI_ISteamRemoteStorage_FileExists,
    SteamAPI_ISteamRemoteStorage_FileSize,
    SteamAPI_ISteamRemoteStorage_FileTime,
    SteamAPI_ISteamRemoteStorage_GetFileCount,
    SteamAPI_ISteamRemoteStorage_GetFileName,
    SteamAPI_ISteamRemoteStorage_GetFileSize,
    SteamAPI_ISteamRemoteStorage_GetQuotaUsed,
    SteamAPI_ISteamRemoteStorage_GetQuotaTotal,
    SteamAPI_ISteamRemoteStorage_IsCloudEnabledForAccount,
    SteamAPI_ISteamRemoteStorage_IsCloudEnabledForApp,
    SteamAPI_ISteamRemoteStorage_UGCDownload,
    SteamAPI_ISteamRemoteStorage_UGCSubscribe,
    SteamAPI_ISteamRemoteStorage_UGCUnsubscribe,
    // -- K6: ISteamScreenshots --
    SteamAPI_ISteamScreenshots_WriteScreenshot,
    SteamAPI_ISteamScreenshots_AddScreenshotToLibrary,
    SteamAPI_ISteamScreenshots_TriggerScreenshot,
    SteamAPI_ISteamScreenshots_HookScreenshots,
    SteamAPI_ISteamScreenshots_IsScreenshotsHooked,
    SteamAPI_ISteamScreenshots_GetScreenshotCount,
    SteamAPI_ISteamScreenshots_GetScreenshotByIndex,
    SteamAPI_ISteamScreenshots_GetScreenshotFilePath,
    SteamAPI_ISteamScreenshots_GetScreenshotThumbnailPath,
    SteamAPI_ISteamScreenshots_TagUser,
    SteamAPI_ISteamScreenshots_TagPublishedFile,
    // -- K7: ISteamMusic (stubs) --
    SteamAPI_ISteamMusic_IsEnabled,
    SteamAPI_ISteamMusic_SetEnabled,
    SteamAPI_ISteamMusic_IsPlaying,
    SteamAPI_ISteamMusic_Play,
    SteamAPI_ISteamMusic_Pause,
    SteamAPI_ISteamMusic_PlayNext,
    SteamAPI_ISteamMusic_PlayPrevious,
    SteamAPI_ISteamMusic_SetVolume,
    SteamAPI_ISteamMusic_GetVolume,
    // -- Steam API flat exports (Phase B3) --
    SteamAPI_Init,
    SteamAPI_Shutdown,
    SteamAPI_RestartAppIfNecessary,
    SteamAPI_RegisterCallback,
    SteamAPI_UnregisterCallback,
    SteamAPI_RegisterCallResult,
    SteamAPI_UnregisterCallResult,
    SteamAPI_RunCallbacks,
    SteamAPI_GetSteamInstallPath,
    SteamAPI_WriteMiniDump,
    SteamAPI_SetMiniDumpComment,
    SteamInternal_CreateInterface,
    SteamInternal_FindOrCreateUserInterface,
    SteamInternal_FindOrCreateGameInterface,
    SteamInternal_ContextInit,
    // -- SteamVR / OpenVR (Phase 5.3.1) --
    SteamVR_Init,
    SteamVR_Shutdown,
    SteamVR_IsHmdPresent,
    SteamVR_IsRuntimeInstalled,
    SteamVR_GetStringForHmdError,
    SteamVR_RuntimePath,
    SteamVR_GetGenericInterface,
    // IVRSystem vtable
    SteamVR_IVRSystem_GetTrackedDeviceClass,
    SteamVR_IVRSystem_IsTrackedDeviceConnected,
    SteamVR_IVRSystem_GetStringTrackedDeviceProperty,
    SteamVR_IVRSystem_GetBoolTrackedDeviceProperty,
    SteamVR_IVRSystem_GetFloatTrackedDeviceProperty,
    SteamVR_IVRSystem_GetInt32TrackedDeviceProperty,
    SteamVR_IVRSystem_GetUint64TrackedDeviceProperty,
    SteamVR_IVRSystem_GetRecommendedRenderTargetSize,
    SteamVR_IVRSystem_GetProjectionMatrix,
    SteamVR_IVRSystem_GetProjectionRaw,
    SteamVR_IVRSystem_GetEyeToHeadTransform,
    SteamVR_IVRSystem_GetDeviceToAbsoluteTrackingPose,
    SteamVR_IVRSystem_PollNextEvent,
    // IVRCompositor vtable
    SteamVR_IVRCompositor_Submit,
    SteamVR_IVRCompositor_WaitGetPoses,
    SteamVR_IVRCompositor_GetFrameTiming,
    SteamVR_IVRCompositor_GetFrameTimeRemaining,
    SteamVR_IVRCompositor_GetCumulativeStats,
    SteamVR_IVRCompositor_CanRenderScene,
    SteamVR_IVRCompositor_SetExplicitTimingMode,
    SteamVR_IVRCompositor_SetExplicitTimingLastPose,
    // IVRChaperone vtable
    SteamVR_IVRChaperone_GetCalibrationState,
    SteamVR_IVRChaperone_GetPlayAreaSize,
    SteamVR_IVRChaperone_GetPlayAreaRect,
    // IVRController vtable
    SteamVR_IVRController_Release,
    SteamVR_IVRController_TriggerHapticPulse,
    SteamVR_IVRController_GetControllerState,
    SteamVR_IVRController_GetControllerStateForNextFrame,
    // IVRInput vtable
    SteamVR_IVRInput_Release,
    SteamVR_IVRInput_SetActionManifestPath,
    SteamVR_IVRInput_GetActionHandle,
    SteamVR_IVRInput_GetActionSetHandle,
    SteamVR_IVRInput_GetDigitalActionData,
    SteamVR_IVRInput_GetAnalogActionData,
    SteamVR_IVRInput_ActivateActionSet,
    SteamVR_IVRInput_GetCurrentActionSet,
    // IVRRenderModels
    SteamVR_IVRRenderModels_LoadIntoTextureD3D11,
    SteamVR_IVRRenderModels_LoadTextureD3D11_Async,
    SteamVR_IVRRenderModels_FreeTextureD3D11,
    // -- K9: IVRRenderModels additional methods --
    SteamVR_IVRRenderModels_LoadRenderModel,
    SteamVR_IVRRenderModels_FreeRenderModel,
    SteamVR_IVRRenderModels_GetRenderModelName,
    SteamVR_IVRRenderModels_GetRenderModelCount,
    SteamVR_IVRRenderModels_GetRenderModelNameByIndex,
    SteamVR_IVRRenderModels_GetRenderModelThumbnail,
    // -- Direct2D / DirectWrite (Phase D2D) --
    DWriteCreateFactory,
    IDWriteFactory_CreateTextFormat,
    IDWriteFactory_CreateTextLayout,
    IDWriteFactory_GetSystemFontCollection,
    IDWriteFactory_RegisterFontCollectionLoader,
    IDWriteFactory_UnregisterFontCollectionLoader,
    IDWriteTextFormat_Release,
    IDWriteTextFormat_SetTextAlignment,
    IDWriteTextFormat_SetParagraphAlignment,
    IDWriteTextFormat_SetReadingDirection,
    IDWriteTextFormat_SetWordWrapping,
    IDWriteTextLayout_Release,
    IDWriteTextLayout_Draw,
    IDWriteTextLayout_GetMetrics,
    IDWriteTextLayout_GetOverhangMetrics,
    IDWriteTextLayout_HitTestPoint,
    IDWriteTextLayout_HitTestTextPosition,
    IDWriteFontCollection_Release,
    IDWriteFontCollection_GetFontFamilyCount,
    IDWriteFontCollection_GetFontFamily,
    IDWriteFontFamily_Release,
    IDWriteFontFamily_GetFontCount,
    IDWriteFontFamily_GetFont,
    D2D1CreateFactory,
    ID2D1Factory_CreateHwndRenderTarget,
    ID2D1Factory_CreateDCRenderTarget,
    ID2D1Factory_CreateSolidColorBrush,
    ID2D1Factory_CreateLinearGradientBrush,
    ID2D1Factory_CreateRadialGradientBrush,
    ID2D1Factory_CreateBitmap,
    ID2D1Factory_CreateBitmapFromWicBitmap,
    ID2D1Factory_Release,
    ID2D1HwndRenderTarget_BeginDraw,
    ID2D1HwndRenderTarget_EndDraw,
    ID2D1HwndRenderTarget_Clear,
    ID2D1HwndRenderTarget_DrawLine,
    ID2D1HwndRenderTarget_DrawRectangle,
    ID2D1HwndRenderTarget_FillRectangle,
    ID2D1HwndRenderTarget_DrawEllipse,
    ID2D1HwndRenderTarget_FillEllipse,
    ID2D1HwndRenderTarget_DrawText,
    ID2D1HwndRenderTarget_DrawBitmap,
    ID2D1HwndRenderTarget_SetTransform,
    ID2D1HwndRenderTarget_GetSize,
    ID2D1HwndRenderTarget_GetDpi,
    ID2D1HwndRenderTarget_Release,
    ID2D1SolidColorBrush_SetColor,
    ID2D1SolidColorBrush_SetOpacity,
    ID2D1SolidColorBrush_Release,
    ID2D1Bitmap_Release,
    ID2D1Bitmap_GetSize,
    ID2D1Bitmap_GetDpi,
    // -- D3D12 Device gap-fill methods (Phase 3.2) --
    D3D12DeviceCreateGraphicsPipelineState,
    D3D12DeviceCreateRootSignature,
    D3D12DeviceGetNodeCount,
    D3D12DeviceCreateCommittedResource,
    D3D12DeviceCreateSampler,
    D3D12DeviceCopyDescriptors,
    D3D12DeviceCopyDescriptorsSimple,
    D3D12DeviceGetDescriptorHandleIncrementSize,
    D3D12DeviceCreateConstantBufferView,
    D3D12DeviceCreateShaderResourceView,
    D3D12DeviceCreateUnorderedAccessView,
    D3D12DeviceCreateDepthStencilView,
    D3D12GraphicsCommandListClearDepthStencilView,
    D3D12GraphicsCommandListDispatch,
    D3D12GraphicsCommandListIASetPrimitiveTopology,
    D3D12GraphicsCommandListRSSetViewports,
    D3D12GraphicsCommandListRSSetScissorRects,
    D3D12GraphicsCommandListSetPipelineState,
    D3D12GraphicsCommandListSetGraphicsRootSignature,
    D3D12GraphicsCommandListSetDescriptorHeaps,
    D3D12GraphicsCommandListSetGraphicsRootDescriptorTable,
    D3D12GraphicsCommandListSetGraphicsRootConstantBufferView,
    D3D12GraphicsCommandListSetGraphicsRoot32BitConstants,
    D3D12GraphicsCommandListIASetVertexBuffers,
    D3D12GraphicsCommandListIASetIndexBuffer,
    D3D12GraphicsCommandListOMSetRenderTargets,
    D3D12GraphicsCommandListOMSetBlendFactor,
    D3D12GraphicsCommandListOMSetStencilRef,
    D3D12GraphicsCommandListSetPredication,
    D3D12GraphicsCommandListSetMarker,
    D3D12GraphicsCommandListBeginQuery,
    D3D12GraphicsCommandListEndQuery,
    D3D12GraphicsCommandListResolveQueryData,
    D3D12GraphicsCommandListExecuteIndirect,
    D3D12GraphicsCommandListCopyResource,
    D3D12GraphicsCommandListCopyTextureRegion,
    // -- D3D12 additional device slots (Phase 3.2 extension) --
    D3D12DeviceCreateComputePipelineState,
    D3D12DeviceCreateCommandSignature,
    D3D12DeviceCreatePipelineLibrary,
    D3D12DeviceCreateHeap,
    D3D12DeviceCreatePlacedResource,
    D3D12DeviceCreateReservedResource,
    D3D12DeviceCreateSharedHandle,
    D3D12DeviceOpenSharedHandle,
    D3D12DeviceOpenSharedHandleByName,
    D3D12DeviceMakeResident,
    D3D12DeviceEvict,
    D3D12DeviceCreateQueryHeap,
    D3D12DeviceCreateCachedPipelineState,
    // -- D3D12 Device remaining slot fixes (Phase 3.2 continued) --
    D3D12DeviceSetStablePowerState,
    D3D12DeviceCreatePipelineLibrary1,
    D3D12Device1CreateShaderResourceView,
    D3D12Device1GetShaderResourceView,
    D3D12Device2CreateShaderResourceView,
    D3D12Device2GetShaderResourceView,
    D3D12Device3CreateShaderResourceView,
    D3D12Device3GetShaderResourceView,
    // -- D3D12 device remaining vtable slots --
    D3D12DeviceGetResourceTiling,
    D3D12DeviceGetAdapterLuid,
    D3D12DeviceGetCopyableFootprints,
    D3D12DeviceGetDeviceRemovedReason,
    D3D12DeviceSetEventOnMultipleFenceCompletion,
    D3D12DeviceSetResidencyPriority,
    D3D12DeviceCreatePipelineState,
    D3D12DeviceOpenExistingHeapFromAddress,
    D3D12DeviceOpenExistingHeapFromFileMapping,
    D3D12DeviceEnqueueMakeResident,
    D3D12DeviceCreateCommandList1,
    D3D12DeviceCreateProtectedResourceSession,
    D3D12DeviceCreateCommittedResource1,
    D3D12DeviceCreateHeap1,
    D3D12DeviceCreateReservedResource1,
    D3D12DeviceGetResourceAllocationInfo,
    D3D12DeviceGetResourceAllocationInfo1,
    D3D12DeviceCreateMetaCommand,
    D3D12DeviceEnumerateMetaCommands,
    D3D12DeviceEnumerateMetaCommandParameters,
    // -- D3D12 graphics command list remaining vtable slots --
    D3D12GraphicsCommandListGetType,
    D3D12GraphicsCommandListSetComputeRootUnorderedAccessView,
    D3D12GraphicsCommandListSetGraphicsRootUnorderedAccessView,
    D3D12GraphicsCommandListSOSetTargets,
    // -- D3D12 fence gap-fill (Phase 3.2) --
    D3D12FenceSetEventOnCompletion,
    D3D12FenceSignal,
    D3D12FenceGetDevice,
    D3D12DescriptorHeapGetDevice,
    D3D12DescriptorHeapGetDesc,
    D3D12DescriptorHeapGetGpuHandleForHeapStart,
    // -- D3D12 command queue gap-fill (Phase 3.2) --
    D3D12CommandQueueWait,
    D3D12CommandQueueGetDevice,
    D3D12CommandQueueGetDesc,
    D3D12ObjectSetName,
    D3D12ObjectGetPrivateData,
    D3D12ObjectSetPrivateData,
    // -- D3D12 state objects / work graphs (Device5/7 + CommandList10) --
    D3D12Device5CreateStateObject,
    D3D12Device7AddToStateObject,
    D3d12ChildObjectGetDevice,
    D3D12GraphicsCommandList10SetProgram,
    D3D12GraphicsCommandList10DispatchGraph,
    // -- DirectML (dml.dll + IDML* COM surface) --
    DmlObjectQueryInterface,
    DmlObjectGetPrivateData,
    DmlObjectSetPrivateData,
    DmlObjectSetPrivateDataInterface,
    DmlObjectSetName,
    DmlObjectGetDevice,
    DmlDeviceCheckFeatureSupport,
    DmlDeviceCreateOperator,
    DmlDeviceCompileOperator,
    DmlDeviceCreateOperatorInitializer,
    DmlDeviceCreateCommandRecorder,
    DmlDeviceCreateBindingTable,
    DmlDeviceEvict,
    DmlDeviceMakeResident,
    DmlDeviceGetDeviceRemovedReason,
    DmlDeviceGetParentDevice,
    DmlDevice1CompileGraph,
    DmlDispatchableGetBindingProperties,
    DmlOperatorInitializerReset,
    DmlCommandRecorderRecordDispatch,
    DmlBindingTableBindInputs,
    DmlBindingTableBindOutputs,
    DmlBindingTableBindTemporaryResource,
    DmlBindingTableBindPersistentResource,
    DmlBindingTableReset,
    DMLCreateDevice,
    DMLCreateDevice1,
    D3D12CommandQueueGetTimestampFrequency,
    D3D12CommandQueueGetClockCalibration,
    // -- D3D9 Device gap-fill methods (Phase 3.3) --
    D3d9DeviceCreateRenderTarget,
    D3d9DeviceCreateDepthStencilSurface,
    D3d9DeviceCreateOffscreenPlainSurface,
    D3d9DeviceGetRenderTargetData,
    D3d9DeviceStretchRect,
    D3d9DeviceGetFrontBufferData,
    D3d9DeviceUpdateSurface,
    D3d9DeviceColorFill,
    D3d9DeviceCreateVertexDeclaration,
    D3d9DeviceCreateVertexShader,
    D3d9DeviceCreatePixelShader,
    D3d9DeviceSetVertexDeclaration,
    D3d9DeviceGetVertexDeclaration,
    // -- D3D11 Query objects (Phase 3.5) --
    D3D11AsynchronousGetData,
    D3D11AsynchronousGetDataSize,
    D3D11QueryGetDesc,
    D3D11PredicateGetDesc,
    // -- D3D9 surface/declaration/shader stub methods (Phase 3.3) --
    D3d9StubReturnOk,
    // -- D3D9 per-object private data (Phase 3.3) --
    D3d9SetPrivateData,
    D3d9GetPrivateData,
    D3d9FreePrivateData,
    D3d9SurfaceGetDesc,
    D3d9SurfaceLockRect,
    D3d9SurfaceUnlockRect,
    D3d9SurfaceGetDC,
    D3d9SurfaceReleaseDC,
    // -- D2D/DWrite integration (Phase 3.6) --
    D2D1Factory_CreateStrokeStyle,
    D2D1Factory_CreateDrawingStateBlock,
    D2D1HwndRenderTarget_CreateSolidColorBrush,
    D2D1HwndRenderTarget_CreateLinearGradientBrush,
    D2D1HwndRenderTarget_CreateRadialGradientBrush,
    D2D1HwndRenderTarget_CreateBitmap,
    D2D1HwndRenderTarget_CreateCompatibleRenderTarget,
    D2D1HwndRenderTarget_PushAxisAlignedClip,
    D2D1HwndRenderTarget_PopAxisAlignedClip,
    D2D1HwndRenderTarget_SetAntialiasMode,
    D2D1HwndRenderTarget_SetTextAntialiasMode,
    D2D1HwndRenderTarget_SetTags,
    D2D1HwndRenderTarget_GetTags,
    D2D1HwndRenderTarget_DrawGlyphRun,
    D2D1HwndRenderTarget_DrawGeometry,
    D2D1HwndRenderTarget_FillGeometry,
    D2D1HwndRenderTarget_FillMesh,
    D2D1HwndRenderTarget_DrawRoundedRectangle,
    D2D1HwndRenderTarget_FillRoundedRectangle,
    D2D1HwndRenderTarget_DrawBitmap_D2D,
    D2D1HwndRenderTarget_CreateLayer,
    D2D1HwndRenderTarget_PushLayer,
    D2D1HwndRenderTarget_PopLayer,
    DWriteFactory_CreateTextFormat_Base,
    DWriteFactory_CreateTypography,
    DWriteTextLayout_SetFontSize,
    DWriteTextLayout_SetFontFamilyName,
    DWriteTextLayout_SetFontWeight,
    DWriteTextLayout_SetFontStyle,
    DWriteTextLayout_SetFontStretch,
    DWriteTextLayout_SetLocaleName,
    DWriteTextLayout_SetMaxWidth,
    DWriteTextLayout_SetMaxHeight,
    DWriteTextLayout_Draw_Inline,
    // -- winspool.drv / Printing (Phase Print) --
    OpenPrinterW,
    ClosePrinter,
    StartDocPrinterW,
    EndDocPrinter,
    StartPagePrinter,
    EndPagePrinter,
    WritePrinter,
    ReadPrinter,
    EnumPrintersW,
    GetPrinterW,
    SetPrinterW,
    AddPrinterW,
    DeletePrinter,
    // -- Raw Input (Phase 4.3) --
    RegisterRawInputDevices,
    GetRawInputData,
    GetRawInputDeviceInfoW,
    GetRegisteredRawInputDevices,
    RegisterClassW,
    RegisterClassExW,
    GetClassInfoW,
    GetClassInfoExW,
    GetDlgItem,
    GetClientRect,
    GetWindowRect,
    EnableWindow,
    IsWindowEnabled,
    GetSystemMenu,
    EnableMenuItem,
    SetDlgItemTextW,
    SetClassLongW,
    CreateWindowExW,
    DialogBoxParamW,
    EndDialog,
    CreateDialogParamW,
    ShowWindow,
    GetDC,
    ReleaseDC,
    /// `GetFocus` — retrieves the HWND that currently has the keyboard focus
    /// for the calling thread's message queue.  The focus HWND is tracked in
    /// the user32 subsystem (`User32Subsystem::focus`); `SetFocus` and the
    /// focus-transition paths (window creation, `ShowWindow`, destruction)
    /// maintain it.  Returns 0 when no window in this thread has focus.
    GetFocus,
    /// `SetFocus` — sets the keyboard focus to the given window, sending
    /// WM_KILLFOCUS to the previously focused window and WM_SETFOCUS to the
    /// newly focused one through the message queue, and returns the previous
    /// focus HWND (0 if there was none).  Fails with 0 + ERROR_INVALID_WINDOW
    /// _HANDLE when the window does not exist.
    SetFocus,
    SetForegroundWindow,
    DestroyWindow,
    InvalidateRect,
    RedrawWindow,
    BeginPaint,
    FillRect,
    EndPaint,
    ScreenToClient,
    SetWindowPos,
    GetSysColor,
    LoadIconW,
    LoadCursorW,
    LoadBitmapW,
    CheckDlgButton,
    GetMessagePos,
    IsWindowVisible,
    GetSystemMetrics,
    MonitorFromWindow,
    /// `MonitorFromRect` — retrieves a handle to the display monitor that has the largest intersection with a specified rectangle.
    MonitorFromRect,
    /// `EnumDisplayMonitors` — enumerates display monitors.
    EnumDisplayMonitors,
    /// `EnumDisplayDevicesW` — enumerates display devices.
    EnumDisplayDevicesW,
    GetMonitorInfoW,
    GetDlgItemTextW,
    IsWindow,
    FindWindowExW,
    CallWindowProcW,
    CreatePopupMenu,
    AppendMenuW,
    TrackPopupMenu,
    // I2 — Menus (new)
    CreateMenu,
    DestroyMenu,
    InsertMenuW,
    InsertMenuItemW,
    ModifyMenuW,
    RemoveMenu,
    GetMenu,
    SetMenu,
    GetSubMenu,
    GetMenuItemCount,
    GetMenuItemID,
    GetMenuState,
    GetMenuStringW,
    DrawMenuBar,
    CheckMenuItem,
    HiliteMenuItem,
    LoadMenuW,
    LoadMenuIndirectW,
    PostQuitMessage,
    PostThreadMessageW,
    /// `PostMessageA` — posts a message to the thread that created the given
    /// window (ANSI variant: identical message plumbing to `PostMessageW`;
    /// the MSG payload carries no text, so no string conversion is needed).
    PostMessageA,
    /// `PostMessageW` — posts a message to the thread that created the given
    /// window.  The message lands in that thread's message queue
    /// (the same `thread_message_queues` machinery as `PostThreadMessageW`,
    /// with the target HWND recorded on the message); a NULL `hwnd` posts to
    /// the calling thread's queue, exactly like Windows.
    PostMessageW,
    SetTimer,
    // --- I8: Animations ---
    AnimateWindow,
    DrawAnimatedRects,
    SystemParametersInfoW,
    SendMessageTimeoutW,
    ExitWindowsEx,
    SetWindowTextW,
    GetWindowLongW,
    SetWindowLongW,
    LoadImageW,
    /// `GetMessageA` — retrieves a message from the calling thread's queue
    /// (ANSI variant).  The MSG structure carries no string data, so the
    /// retrieval loop is identical to `GetMessageW`; the result is written
    /// into the same MSG layout in guest memory.
    GetMessageA,
    GetMessageW,
    TranslateMessage,
    PeekMessageW,
    DispatchMessageW,
    DefWindowProcW,
    SendMessageW,
    GetDeviceCaps,
    SelectObject,
    CreateFontW,
    CreateFontIndirectW,
    DeleteObject,
    SetBkMode,
    SetTextColor,
    SetBkColor,
    GetStockObject,
    CreateSolidBrush,
    FrameRect,
    DrawTextA,
    GetTextExtentPoint32A,
    GetTextExtentPoint32W,
    CreatePen,
    CreateRectRgn,
    CreateRoundRectRgn,
    SetMapMode,
    GetTextMetricsW,
    ExtTextOutW,
    GetTextExtentExPointW,
    SetRect,
    CopyRect,
    InflateRect,
    OffsetRect,
    DrawTextW,
    PatBlt,
    BitBlt,
    StretchBlt,
    Rectangle,
    /// `Ellipse` — draws an ellipse bounded by the given rectangle into the
    /// DC's window surface using the selected pen color for the outline.
    Ellipse,
    /// `InvertRect` — inverts the pixel colors of a rectangle in the DC's
    /// window surface.
    InvertRect,
    /// `GetRgnBox` — retrieves the bounding rectangle of a region.
    GetRgnBox,
    /// `CombineRgn` — combines two regions into a third region with the
    /// given combine mode, returning the result type (NULLREGION/SIMPLEREGION/
    /// COMPLEXREGION/ERROR).
    CombineRgn,
    /// `GetObjectW` — retrieves the properties of a GDI object into the
    /// caller's buffer (LOGBRUSH for brushes, LOGFONT for fonts, BITMAP for
    /// bitmaps, RECT for regions).
    GetObjectW,
    /// `AlphaBlend` — blends a source bitmap into the destination DC with a
    /// per-pixel alpha channel (BLENDFUNCTION).  Rasterizes into the DC's
    /// window surface following the documented alpha-compositing formula.
    AlphaBlend,
    /// `TransparentBlt` — copies a bitmap region into the destination DC,
    /// making pixels matching the given transparent color invisible.
    TransparentBlt,
    /// `GdiFlush` — flushes any pending GDI drawing (a no-op success: the
    /// runtime rasterizes drawing calls synchronously, so nothing is
    /// pending).
    GdiFlush,
    /// `GdiComment` — appends a comment to the enhanced metafile of the DC
    /// (a no-op success for non-metafile DCs).
    GdiComment,
    /// `CreateCompatibleBitmap` — creates a bitmap compatible with the given
    /// DC's pixel format (32bpp BGRA, matching the memory-DC surfaces).
    CreateCompatibleBitmap,
    /// `CreateDCW` — creates a device context for the named display driver
    /// (e.g. "DISPLAY"); unknown drivers fail with ERROR_INVALID_PARAMETER
    /// and return NULL, exactly like Windows.
    CreateDCW,
    /// `GetPixel` — reads the color of the pixel at (x, y) from the DC's
    /// window surface as a COLORREF (0x00BBGGRR); CLR_INVALID when the
    /// surface has no content.
    GetPixel,
    /// `SetPixel` — sets the pixel at (x, y) in the DC's window surface to
    /// the given COLORREF, returning the set color.
    SetPixel,
    /// `GetCharWidthW` — retrieves the advance widths of a run of characters
    /// in the DC's selected font (from the same text-metrics machinery as
    /// `GetTextExtentPoint32W`).
    GetCharWidthW,
    /// `GetGlyphOutlineW` — retrieves glyph outline data.  The runtime's
    /// bitmap-font model cannot produce outlines, so this returns
    /// GDI_ERROR (0xFFFFFFFF) with ERROR_CANNOT_COMPLETE, the documented
    /// failure for bitmap fonts.
    GetGlyphOutlineW,
    /// `DrawTextExW` — extended `DrawTextW` with additional formatting
    /// flags (DT_CALCRECT etc.) through the same text-drawing machinery.
    DrawTextExW,
    GetTextColor,
    GetBkColor,
    GetBkMode,
    MoveToEx,
    LineTo,
    MulDiv,
    SetCurrentDirectoryW,
    GetCurrentDirectoryW,
    GetFullPathNameW,
    GetFileAttributesW,
    GetFileAttributesExW,
    SetFileAttributesW,
    SetErrorMode,
    GetACP,
    GetOEMCP,
    IsValidCodePage,
    GetCPInfo,
    GetStringTypeW,
    LCMapStringW,
    LCMapStringEx,
    LocaleNameToLCID,
    SetDefaultDllDirectories,
    GetSystemDirectoryW,
    GetWindowsDirectoryW,
    GetTempPathW,
    GetTempFileNameW,
    GetModuleFileNameA,
    GetModuleFileNameW,
    GetDiskFreeSpaceW,
    GetDiskFreeSpaceExW,
    GetFileSize,
    FindFirstFileW,
    FindNextFileW,
    FindClose,
    LoadLibraryA,
    LoadLibraryW,
    LoadLibraryExA,
    LoadLibraryExW,
    FreeLibrary,
    GetModuleHandleExA,
    GetModuleHandleExW,
    InitCommonControls,
    InitCommonControlsEx,
    // --- I4: Common Controls (ImageList) ---
    ImageList_Create,
    ImageList_Destroy,
    ImageList_Add,
    ImageList_Remove,
    ImageList_GetImageCount,
    ImageList_SetImageCount,
    ImageList_GetImageInfo,
    ImageList_BeginDrag,
    ImageList_DragEnter,
    ImageList_DragLeave,
    ImageList_DragMove,
    ImageList_DragShowNolock,
    ImageList_EndDrag,
    ImageList_GetDragImage,
    ImageList_SetDragCursorImage,
    ImageList_ReplaceIcon,
    ImageList_SetBkColor,
    ImageList_GetBkColor,
    ImageList_Draw,
    ImageList_DrawEx,
    OleInitialize,
    OleUninitialize,
    CoCreateInstance,
    CoTaskMemFree,
    VariantClear,
    CommandLineToArgvW,
    IsUserAnAdmin,
    SHGetFileInfoW,
    SHGetFolderPathW,
    SHGetPathFromIDListW,
    SHGetSpecialFolderLocation,
    ShellLinkQueryInterface,
    GraphicsObjectQueryInterface,
    ShellLinkAddRef,
    ShellLinkRelease,
    ShellLinkGetPathW,
    ShellLinkGetIDList,
    ShellLinkSetIDList,
    ShellLinkGetDescriptionW,
    ShellLinkSetDescriptionW,
    ShellLinkGetWorkingDirectoryW,
    ShellLinkSetWorkingDirectoryW,
    ShellLinkGetArgumentsW,
    ShellLinkSetArgumentsW,
    ShellLinkGetHotkey,
    ShellLinkSetHotkey,
    ShellLinkGetShowCmd,
    ShellLinkSetShowCmd,
    ShellLinkGetIconLocationW,
    ShellLinkSetIconLocationW,
    ShellLinkSetRelativePath,
    ShellLinkResolve,
    ShellLinkSetPathW,
    ShellLinkPersistGetClassID,
    ShellLinkPersistIsDirty,
    ShellLinkPersistLoad,
    ShellLinkPersistSave,
    ShellLinkPersistSaveCompleted,
    ShellLinkPersistGetCurFile,
    MultiByteToWideChar,
    WideCharToMultiByte,
    LstrcmpiW,
    LstrcmpW,
    LstrlenW,
    LstrcpyA,
    LstrcpyW,
    LstrcpynW,
    LstrcatW,
    CharUpperW,
    GetCommandLineA,
    GetCommandLineW,
    OutputDebugStringA,
    OutputDebugStringW,
    SetEnvironmentVariableW,
    GetEnvironmentVariableW,
    GetEnvironmentStringsW,
    FreeEnvironmentStringsW,
    CharNextW,
    CharPrevW,
    CreateDirectoryW,
    RemoveDirectoryW,
    DeleteFileW,
    WritePrivateProfileStringW,
    CreateProcessW,
    CreateThread,
    CreateIoCompletionPort,
    PostQueuedCompletionStatus,
    GetQueuedCompletionStatus,
    GetQueuedCompletionStatusEx,
    CreateEventA,
    CreateEventW,
    OpenEventA,
    OpenEventW,
    SetEvent,
    ResetEvent,
    IsDebuggerPresent,
    InitOnceBeginInitialize,
    InitOnceComplete,
    InitOnceExecuteOnce,
    InitializeSRWLock,
    AcquireSRWLockExclusive,
    ReleaseSRWLockExclusive,
    AcquireSRWLockShared,
    ReleaseSRWLockShared,
    TryAcquireSRWLockExclusive,
    TryAcquireSRWLockShared,
    WaitForSingleObject,
    GetExitCodeThread,
    GetExitCodeProcess,
    TerminateProcess,
    GetModuleHandleA,
    GetModuleHandleW,
    GetProcAddress,
    EnumProcesses,
    EnumProcessModules,
    GetModuleBaseNameA,
    /// `GetModuleBaseNameW` — retrieves the base name of the specified module
    /// (the module's file name without the directory path) as a UTF-16
    /// string.  Resolves the module from the runtime's module-handle tables;
    /// unknown handles fail with ERROR_INVALID_HANDLE.
    GetModuleBaseNameW,
    WsprintfW,
    CreateFileW,
    AreFileApisANSI,
    FlushFileBuffers,
    GetCommState,
    SetCommState,
    GetCommTimeouts,
    SetCommTimeouts,
    PurgeComm,
    ClearCommError,
    EscapeCommFunction,
    GetCurrentPackageId,
    GetSystemTimeAsFileTime,
    GetSystemTimePreciseAsFileTime,
    GetTimeZoneInformation,
    GetTempPath2W,
    CompareFileTime,
    SetFileTime,
    RegCreateKeyExA,
    RegCreateKeyExW,
    RegOpenKeyA,
    RegOpenKeyExA,
    RegOpenKeyExW,
    RegSetValueExA,
    RegSetValueExW,
    RegQueryValueExA,
    RegQueryValueExW,
    RegCloseKey,
    InitializeSecurityDescriptor,
    SetSecurityDescriptorDacl,
    SystemFunction036,
    SetFilePointer,
    ReadFile,
    WriteFile,
    /// `GetOverlappedResult` — reports the result of an overlapped
    /// operation; with bWait=TRUE the thread parks on the scheduler's
    /// `Overlapped` wait until the request completes.
    GetOverlappedResult,
    LocalAlloc,
    LocalLock,
    LocalUnlock,
    LocalFree,
    GlobalAlloc,
    GlobalLock,
    GlobalUnlock,
    GlobalFree,
    CloseHandle,
    SetHandleInformation,
    DuplicateHandle,
    Calloc,
    Free,
    Malloc,
    Realloc,
    SetNewMode,
    CSpecificHandler,
    PArgc,
    PArgv,
    Cexit,
    ConfigureNarrowArgv,
    CrtAtExit,
    CrtExit,
    InitializeNarrowEnvironment,
    Initterm,
    InittermE,
    SetAppType,
    SetInvalidParameterHandler,
    Abort,
    Exit,
    Signal,
    AcrtIobFunc,
    PCommode,
    PFmode,
    StdioCommonVfprintf,
    Fwrite,
    Strlen,
    Strncmp,
    PEnviron,
    SetUserMathErr,
    DeleteCriticalSection,
    EnterCriticalSection,
    TryEnterCriticalSection,
    GetVersion,
    GetLastError,
    SetLastError,
    WsaStartup,
    WsaCleanup,
    WsaGetLastError,
    WsaSetLastError,
    Htonl,
    Htons,
    Getaddrinfo,
    Freeaddrinfo,
    Bind,
    Connect,
    ConnectEx,
    DisconnectEx,
    Getsockname,
    Ioctlsocket,
    Ntohl,
    Ntohs,
    Closesocket,
    Recv,
    Send,
    Select,
    Setsockopt,
    Shutdown,
    Socket,
    WsaRecv,
    WsaRecvFrom,
    WsaSend,
    WsaSendTo,
    WsaFdIsSet,
    WsaIoctl,
    WsaSocketA,
    // -- ws2_32.dll: socket lifecycle + DNS/service helpers (net-sys) -------
    /// `accept` — accepts a pending connection off a listening socket,
    /// minting a win32-table socket handle for the accepted side.
    Accept,
    /// `WSAAccept` — `accept` with the documented condition callback
    /// (CF_ACCEPT / CF_REJECT / CF_DEFER).
    WsaAccept,
    /// `listen` — transitions a bound socket to the listening state.
    Listen,
    /// `getsockopt` — the documented socket-option queries (SO_ERROR,
    /// SO_TYPE, SO_ACCEPTCONN, buffers, TCP_NODELAY, IP_TTL).
    Getsockopt,
    /// `WSAConnect` — `connect` with caller/callee data buffers.
    WsaConnect,
    /// `WSAPoll` — WSAPOLLFD readiness polling over the select core.
    WsaPoll,
    /// `WSASocketW` — wide variant of WSASocketA (protocol info struct).
    WsaSocketW,
    /// `WSADuplicateSocketW` — fills a WSAPROTOCOL_INFOW for the socket.
    WsaDuplicateSocketW,
    /// `gethostbyname` — classic HOSTENT resolution from the guest DNS
    /// records.
    Gethostbyname,
    /// `gethostbyaddr` — reverse HOSTENT lookup.
    Gethostbyaddr,
    /// `gethostname` — the configured guest host name.
    Gethostname,
    /// `getnameinfo` — sockaddr → host/service strings.
    Getnameinfo,
    /// `getprotobyname` — protocol-name conversion.
    Getprotobyname,
    /// `getservbyname` — service-name conversion.
    Getservbyname,
    /// `inet_addr` — dotted-quad → network-order address.
    InetAddr,
    /// `inet_ntoa` — network-order address → dotted-quad string.
    InetNtoa,
    // -- secur32.dll SSPI (net-sys) ----------------------------------------
    /// `AcquireCredentialsHandleW` — mints a credential handle.
    AcquireCredentialsHandleW,
    /// `FreeCredentialsHandle` — releases a credential handle.
    FreeCredentialsHandle,
    /// `InitializeSecurityContextW` — client NTLM/Negotiate handshake.
    InitializeSecurityContextW,
    /// `AcceptSecurityContext` — server NTLM/Negotiate handshake.
    AcceptSecurityContext,
    /// `CompleteAuthToken` — parks an out-of-band handshake token.
    CompleteAuthToken,
    /// `DeleteSecurityContext` — destroys a security context.
    DeleteSecurityContext,
    /// `ImpersonateSecurityContext` — the guest already runs as the user.
    ImpersonateSecurityContext,
    /// `RevertSecurityContext` — no-op counterpart of impersonation.
    RevertSecurityContext,
    /// `QueryContextAttributesW` — sizes/names/session-key/package-info.
    QueryContextAttributesW,
    /// `MakeSignature` — signs a message (NTLMSSP_MESSAGE_SIGNATURE).
    MakeSignature,
    /// `VerifySignature` — verifies a signed message envelope.
    VerifySignature,
    /// `EncryptMessage` — seals a message (signature + PRF keystream).
    EncryptMessage,
    /// `DecryptMessage` — unseals and verifies an encrypted message.
    DecryptMessage,
    /// `EnumerateSecurityPackagesW` — the guest-visible package table.
    EnumerateSecurityPackagesW,
    /// `GetUserNameExW` — extended user-name formats from the guest env.
    GetUserNameExW,
    // -- netapi32.dll (net-sys) --------------------------------------------
    /// `NetApiBufferFree` — frees netapi buffers via the guest heap.
    NetApiBufferFree,
    /// `NetServerEnum` — the empty guest server enumeration.
    NetServerEnum,
    /// `NetWkstaGetInfo` — workstation info from the guest environment.
    NetWkstaGetInfo,
    /// `NetUserGetInfo` — guest user info structures.
    NetUserGetInfo,
    // -- iphlpapi.dll (net-sys) --------------------------------------------
    /// `GetAdaptersInfo` — the classic adapter chain from the guest config.
    GetAdaptersInfo,
    /// `GetAdaptersAddresses` — the Vista adapter structures.
    GetAdaptersAddresses,
    /// `GetIfTable` — the interface table.
    GetIfTable,
    /// `GetIfEntry` — one interface row.
    GetIfEntry,
    /// `GetIpAddrTable` — the IPv4 address table.
    GetIpAddrTable,
    /// `GetIpForwardTable` — the IPv4 route table.
    GetIpForwardTable,
    /// `GetNetworkParams` — host/domain/DNS fixed info.
    GetNetworkParams,
    /// `GetBestInterface` — the interface for a destination.
    GetBestInterface,
    /// `GetBestRoute` — the route for a destination.
    GetBestRoute,
    /// `GetRTTAndHopCount` — the guest-modeled reachability probe.
    GetRTTAndHopCount,
    /// `NotifyAddrChange` — pending address-change notification.
    NotifyAddrChange,
    /// `NotifyRouteChange` — pending route-change notification.
    NotifyRouteChange,
    /// `CancelMibChangeNotify2` — cancels a pending change notification.
    CancelMibChangeNotify2,
    GetCurrentThread,
    GetCurrentThreadId,
    GetCurrentProcessId,
    ProcessIdToSessionId,
    GetCurrentProcess,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    VerSetConditionMask,
    VerifyVersionInfoW,
    IsProcessorFeaturePresent,
    GetProcessHeap,
    GetProcessHeaps,
    HeapAlloc,
    HeapFree,
    HeapReAlloc,
    HeapSize,
    // -- usp10.dll Uniscribe (P0.3) --
    ScriptStringAnalyse,
    ScriptStringFree,
    ScriptStringOut,
    ScriptString_pSize,
    ScriptItemize,
    ScriptShape,
    ScriptPlace,
    ScriptLayout,
    ScriptBreak,
    ScriptGetProperties,
    ScriptRecordDigitSubstitution,
    ScriptApplyDigitSubstitution,
    ScriptCacheGetHeight,
    ScriptFreeCache,
    GetStartupInfoW,
    InitializeSListHead,
    GetStdHandle,
    GetFileType,
    GetFileInformationByHandle,
    GetTickCount,
    GetTickCount64,
    InitializeCriticalSection,
    InitializeCriticalSectionAndSpinCount,
    InitializeCriticalSectionEx,
    LeaveCriticalSection,
    SleepConditionVariableCS,
    WakeAllConditionVariable,
    EncodePointer,
    DecodePointer,
    UnhandledExceptionFilter,
    SetUnhandledExceptionFilter,
    /// `AddVectoredExceptionHandler` / `RtlAddVectoredExceptionHandler` — registers a
    /// vectored exception handler for the guest. Dispatched through the
    /// `SehSubsystem` VEH chain.
    AddVectoredExceptionHandler,
    /// `RemoveVectoredExceptionHandler` / `RtlRemoveVectoredExceptionHandler` —
    /// unregisters a vectored exception handler previously registered by
    /// `AddVectoredExceptionHandler`.
    RemoveVectoredExceptionHandler,
    /// `AddVectoredContinueHandler` / `RtlAddVectoredContinueHandler` — registers
    /// a vectored continue handler that executes after all exception handlers
    /// (VEH + SEH) have processed the exception.
    AddVectoredContinueHandler,
    /// `RemoveVectoredContinueHandler` / `RtlRemoveVectoredContinueHandler` —
    /// unregisters a vectored continue handler.
    RemoveVectoredContinueHandler,
    Beep,
    Sleep,
    TlsAlloc,
    TlsGetValue,
    TlsSetValue,
    TlsFree,
    FlsAlloc,
    FlsGetValue,
    FlsSetValue,
    FlsFree,
    SetFileCompletionNotificationModes,
    RtlNtStatusToDosError,
    VirtualAlloc,
    VirtualFree,
    VirtualProtect,
    VirtualQuery,
    ExitProcess,
    MessageBoxW,
    MessageBoxIndirectW,
    RegEnumKeyExW,
    RegDeleteKeyW,
    RegDeleteValueW,
    GetUserNameW,
    GetComputerNameW,
    GetLongPathNameW,
    GetShortPathNameW,
    CreatePipe,
    GetFileVersionInfoSizeW,
    GetFileVersionInfoW,
    VerQueryValueW,
    CoInitializeEx,
    CoUninitialize,
    SHGetKnownFolderPath,
    ShellExecuteExW,
    // -- shlwapi.dll: path helpers -------------------------------------------
    /// `PathAppendW` — appends a relative path element to a path in place,
    /// inserting a single backslash separator; an absolute `pszMore`
    /// replaces the path; a leading `..` pops the last element first.
    PathAppendW,
    /// `PathCombineW` — combines a directory and a file name into `pszOut`
    /// following the Windows append rules (absolute file replaces the
    /// directory, `..` pops, empty directory yields `\file`); returns
    /// `pszOut` or NULL when nothing was combined.
    PathCombineW,
    /// `PathFileExistsW` — TRUE when the resolved guest path names an
    /// existing file or directory.
    PathFileExistsW,
    /// `PathFindExtensionW` — pointer to the extension of a path (the last
    /// dot after the last directory separator, colon, or space), or a
    /// pointer to the trailing NUL when the path has no extension.
    PathFindExtensionW,
    /// `PathFindFileNameW` — pointer to the last path component (after the
    /// last `\`, `/`, or `:`), or the whole string when no separator exists.
    PathFindFileNameW,
    /// `PathRemoveFileSpecW` — removes the trailing file name (and the
    /// separator before it); returns TRUE when a component was removed and
    /// FALSE (path unchanged) for roots and separator-less paths.
    PathRemoveFileSpecW,
    /// `PathRemoveExtensionW` — removes the extension from a path in place,
    /// including the leading dot; no-op when the path has no extension.
    PathRemoveExtensionW,
    /// `PathRemoveBlanksW` — removes all leading and trailing spaces from a
    /// path in place.
    PathRemoveBlanksW,
    /// `PathIsDirectoryW` — TRUE when the resolved guest path names an
    /// existing directory (uses the file attributes of the win32
    /// subsystem).
    PathIsDirectoryW,
    /// `PathIsRelativeW` — TRUE when the path is not drive-qualified, not
    /// UNC, and does not begin with a separator.
    PathIsRelativeW,
    /// `PathCanonicalizeW` — canonicalizes a path in place (`.`, `..`, and
    /// duplicate separators collapsed, separators normalized to `\`);
    /// returns FALSE when the input is not an absolute path.
    PathCanonicalizeW,
    /// `PathMatchSpecW` — TRUE when the path matches a DOS-style wildcard
    /// pattern (`*`, `?`, and `;`-separated alternates).
    PathMatchSpecW,
    /// `PathStripPathW` — removes the directory portion of a path in place,
    /// leaving only the final component.
    PathStripPathW,
    /// `PathGetDriveNumberW` — the drive index (0 for `A:`, 1 for `B:`,
    /// ...) of a drive-qualified path, or -1 when the path has no drive.
    PathGetDriveNumberW,
    /// `PathAddBackslashW` — appends a trailing backslash when the path
    /// does not already end with one; returns the path or NULL when the
    /// path is too long.
    PathAddBackslashW,
    /// `PathRemoveBackslashW` — removes the trailing backslash from a path
    /// (but not a root like `C:\`); returns the path or NULL.
    PathRemoveBackslashW,
    /// `PathSkipRootW` — pointer to the first path component after the
    /// root (drive `X:\` or UNC `\\server\share\`); NULL when the path
    /// has no root.
    PathSkipRootW,
    /// `PathIsRootW` — TRUE when the path is a root path (`C:\`, `\`,
    /// `\\server\share`, or the UNC root forms).
    PathIsRootW,
    /// `ChrCmpIW` — case-insensitive comparison of two characters; TRUE
    /// when they match (the case_fold machinery, like lstrcmpiW on single
    /// characters).
    ChrCmpIW,
    /// `IntlStrEqWorkerW` — case-insensitive (or case-sensitive when
    /// `bCaseSensitive`) prefix comparison of `nChar` characters; TRUE when
    /// the strings compare equal over that length.
    IntlStrEqWorkerW,
    /// `IsCharAlphaW` — TRUE when the character is alphabetic (Unicode
    /// letter class).
    IsCharAlphaW,
    /// `IsCharAlphaNumericW` — TRUE when the character is alphabetic or a
    /// decimal digit.
    IsCharAlphaNumericW,
    /// `IsCharLowerW` — TRUE when the character is a lowercase letter.
    IsCharLowerW,
    /// `IsCharUpperW` — TRUE when the character is an uppercase letter.
    IsCharUpperW,
    /// `IsCharSpaceW` — TRUE when the character is a whitespace character.
    IsCharSpaceW,
    /// `ParseURLW` — parses a URL into its scheme and location; writes the
    /// scheme into the URL_COMPONENTS structure and returns URL_SUCCESS (0)
    /// for supported schemes or URL_INVALID_URL when no scheme is present.
    ParseURLW,
    /// `StrChrW` — pointer to the first occurrence of a character in a
    /// string (case-sensitive), or NULL.
    StrChrW,
    /// `StrChrIW` — case-insensitive first-occurrence search.
    StrChrIW,
    /// `StrRChrW` — pointer to the LAST occurrence of a character in a
    /// string at or before `chStart` (case-sensitive), or NULL.
    StrRChrW,
    /// `StrStrW` — pointer to the first occurrence of a substring
    /// (case-sensitive), or NULL.
    StrStrW,
    /// `StrStrIW` — case-insensitive substring search.
    StrStrIW,
    /// `StrCmpIW` — case-insensitive string comparison (0 when equal).
    StrCmpIW,
    /// `StrCmpNIW` — case-insensitive comparison of the first `nChar`
    /// characters (0 when equal).
    StrCmpNIW,
    /// `StrCmpNW` — case-sensitive comparison of the first `nChar`
    /// characters (0 when equal).
    StrCmpNW,
    /// `StrCmpW` — case-sensitive string comparison (0 when equal).
    StrCmpW,
    /// `StrCpyNW` — copies at most `cchMax` characters (including the NUL
    /// terminator) into the destination; returns the destination pointer.
    StrCpyNW,
    /// `StrCpyW` — copies a string into the destination; returns the
    /// destination pointer.
    StrCpyW,
    /// `StrCatW` — concatenates a source string onto the destination;
    /// returns the destination pointer.
    StrCatW,
    /// `StrToIntW` — parses an optional sign followed by decimal digits
    /// into an i32; returns 0 when no digits are present.
    StrToIntW,
    /// `StrFromTimeIntervalW` — formats a time interval (milliseconds) as
    /// `d:hh:mm:ss` / `hh:mm:ss` with the requested significant digits;
    /// returns the number of characters written.
    StrFromTimeIntervalW,
    /// `SHRegGetValueW` — reads a registry value with subkey-path
    /// resolution (SRRF_RT_* type checking); returns ERROR_SUCCESS or a
    /// Win32 error code.
    SHRegGetValueW,
    /// `SHRegSetValueW` — writes a registry value, creating intermediate
    /// keys as needed; returns ERROR_SUCCESS or a Win32 error code.
    SHRegSetValueW,
    /// `SHDeleteKeyW` — deletes a registry key (and its subkeys).
    SHDeleteKeyW,
    /// `SHDeleteEmptyKeyW` — deletes a registry key only when it has no
    /// subkeys or values.
    SHDeleteEmptyKeyW,
    /// `SHSearchMapInt` — looks up an integer key in a (key, value) pair
    /// table (two parallel int arrays); returns the first matching value,
    /// or -1 when the key is not found.
    SHSearchMapInt,
    /// `GetMenuContextHelpId` — returns 0 (no context help id).
    GetMenuContextHelpId,
    /// `SetMenuContextHelpId` — no-op; returns TRUE.
    SetMenuContextHelpId,
    /// `UrlCanonicalizeW` — canonicalizes a URL (lowercases the scheme and
    /// host, collapses duplicate slashes, resolves `.`/`..` segments) into
    /// the output buffer; returns URL_SUCCESS or URL_E_INVALIDURL.
    UrlCanonicalizeW,
    /// `UrlCombineW` — combines a base URL and a relative URL into the
    /// output buffer following RFC 3986 resolution; returns URL_SUCCESS or
    /// URL_E_INVALIDURL.
    UrlCombineW,
    GetNativeSystemInfo,
    GetSystemInfo,
    IsWow64Process,
    GetProductInfo,
    /// `GetVersionExW` — fills an `OSVERSIONINFOW` (or `OSVERSIONINFOEXW`) structure
    /// with the host OS version information.  Steam.exe queries this during startup
    /// to decide which code paths to activate; returning a plausible Windows 10
    /// build avoids early termination.
    GetVersionExW,
    // -- Multi-Process / IPC variants (Phase 1.1) -------------------------------
    /// `CreateNamedPipeW` — creates a named-pipe server endpoint.
    CreateNamedPipeW,
    /// `ConnectNamedPipe` — waits for a client to connect to the named pipe.
    ConnectNamedPipe,
    /// `DisconnectNamedPipe` — disconnects the server end of a named pipe.
    DisconnectNamedPipe,
    /// `CallNamedPipeW` — convenience: connect, write, read, disconnect.
    CallNamedPipeW,
    /// `WaitNamedPipeW` — waits for a named-pipe server to become available.
    WaitNamedPipeW,
    /// `GetNamedPipeInfo` — retrieves named pipe buffer/mode/instance info.
    GetNamedPipeInfo,
    /// `SetNamedPipeHandleState` — sets named pipe read mode, wait mode, etc.
    SetNamedPipeHandleState,
    /// `PeekNamedPipe` — reads pipe data without consuming it.
    PeekNamedPipe,
    /// `CreateFileMappingW` — creates or opens a named shared-memory section.
    CreateFileMappingW,
    /// `MapViewOfFile` — maps a view of a file-mapping object into the guest address space.
    MapViewOfFile,
    /// `UnmapViewOfFile` — unmaps a mapped view.
    UnmapViewOfFile,
    /// `OpenProcess` — returns a handle to an existing process object.
    OpenProcess,
    /// `WaitForMultipleObjects` — waits on an array of handles.
    WaitForMultipleObjects,
    /// `CreateProcessA` — ANSI variant of CreateProcessW (converts to UTF-16 internally).
    CreateProcessA,
    // -- Window Manager Enhancements (Phase 2.2) ---------------------------------
    /// `SetLayeredWindowAttributes` — sets opacity and transparency color key for a layered window.
    SetLayeredWindowAttributes,
    /// `UpdateLayeredWindow` — updates position, size, shape, content, and translucency of a layered window.
    UpdateLayeredWindow,
    /// `SetWindowRgn` — sets the window region (non-rectangular shape).
    SetWindowRgn,
    /// `PrintWindow` — copies the visual contents of a window into a device context.
    PrintWindow,
    /// `Shell_NotifyIconW` — sends a notification to the taskbar's notification area (system tray).
    ShellNotifyIconW,
    /// `SetWindowCompositionAttribute` — sets window composition attributes (e.g., blur behind).
    SetWindowCompositionAttribute,
    /// `GetWindowPlacement` — retrieves the window's placement (show state, position).
    GetWindowPlacement,
    /// `SetWindowPlacement` — sets the window's placement (show state, position).
    SetWindowPlacement,
    /// `SetProcessDPIAware` — marks the process as DPI aware (no-op on macOS).
    SetProcessDPIAware,
    /// `GetDpiForWindow` — returns the DPI for a given window.
    GetDpiForWindow,
    /// `SetProcessDPIAwareness` — sets the process DPI awareness level (u32-based API).
    SetProcessDPIAwareness,
    /// `GetDpiForMonitor` — returns the DPI for a given monitor.
    GetDpiForMonitor,
    /// `SetThreadDpiAwarenessContext` — sets the thread's DPI awareness context.
    SetThreadDpiAwarenessContext,
    /// `GetThreadDpiAwarenessContext` — returns the thread's DPI awareness context.
    GetThreadDpiAwarenessContext,
    /// `EnableNonClientDpiScaling` — enables DPI scaling for the non-client area.
    EnableNonClientDpiScaling,
    /// `AdjustWindowRectExForDpi` — calculates required size for a given DPI.
    AdjustWindowRectExForDpi,
    // -- Phase 2.3: Window Manager Extensions (user32.dll) ---------------------
    /// `BringWindowToTop` — brings a window to the top of the z-order.
    BringWindowToTop,
    /// `GetTopWindow` — retrieves the top-level (front-most) child window of a parent.
    GetTopWindow,
    /// `GetNextWindow` — retrieves the next/previous window in the z-order.
    GetNextWindow,
    /// `GetWindow` — retrieves a window relationship (GW_CHILD, GW_OWNER, GW_HWNDNEXT, …).
    GetWindow,
    /// `GetWindowTextW` — retrieves the title/text of a window.
    GetWindowTextW,
    /// `GetWindowTextA` — retrieves the title/text of a window (ANSI
    /// variant): the wide title is converted to the ANSI code page
    /// (CP_ACP, CP1252 for the default locale) and copied into the caller's
    /// buffer with the Windows truncation/NUL contract.
    GetWindowTextA,
    /// `GetWindowTextLengthW` — retrieves the length (in chars) of a window's title/text.
    GetWindowTextLengthW,
    /// `GetUpdateRect` — retrieves the update rectangle of a window.
    GetUpdateRect,
    /// `ValidateRect` — validates (removes paint) for a rectangle.
    ValidateRect,
    /// `InvalidateRgn` — invalidates a window region, queuing a paint message.
    InvalidateRgn,
    /// `SetWindowLongPtrW` — sets a window long value (e.g., GWLP_HWNDPARENT).
    SetWindowLongPtrW,
    /// `GetWindowLongPtrW` — retrieves a window long value.
    GetWindowLongPtrW,
    /// `GetParent` — retrieves the parent HWND of a window.
    GetParent,
    /// `SetParent` — changes the parent HWND of a window.
    SetParent,
    // -- WinHTTP (winhttp.dll) --------------------------------------------------
    WinHttpOpen,
    WinHttpCloseHandle,
    WinHttpConnect,
    WinHttpOpenRequest,
    WinHttpSendRequest,
    WinHttpReceiveResponse,
    WinHttpReadData,
    WinHttpQueryDataAvailable,
    WinHttpQueryHeaders,
    WinHttpSetOption,
    WinHttpSetStatusCallback,
    // -- WinINet (wininet.dll) ---------------------------------------------------
    InternetOpenW,
    InternetConnectW,
    HttpOpenRequestW,
    HttpSendRequestW,
    InternetReadFile,
    InternetCloseHandle,
    // -- Phase 3.1: Extended WinHTTP APIs ---------------------------------------
    /// `WinHttpAddRequestHeaders` — adds one or more HTTP request headers.
    WinHttpAddRequestHeaders,
    /// `WinHttpWriteData` — writes request body data.
    WinHttpWriteData,
    /// `WinHttpSetCredentials` — passes authorization credentials to the server/proxy.
    WinHttpSetCredentials,
    /// `WinHttpQueryAuthSchemes` — queries the supported authentication schemes.
    WinHttpQueryAuthSchemes,
    // -- Phase 3.1: Extended WinINet APIs ---------------------------------------
    /// `InternetQueryDataAvailable` — queries available data on a request handle.
    InternetQueryDataAvailable,
    /// `InternetSetOptionW` — sets an internet option.
    InternetSetOptionW,
    /// `InternetGetLastResponseInfoW` — retrieves the last response error info.
    InternetGetLastResponseInfoW,
    /// `InternetSetStatusCallback` — registers a status callback function.
    InternetSetStatusCallback,
    /// `InternetCrackUrlW` — cracks a URL into its component parts.
    InternetCrackUrlW,
    /// `InternetCanonicalizeUrlW` — canonicalizes a URL.
    InternetCanonicalizeUrlW,
    // -- J1: WinHTTP WebSocket extensions --------------------------------------
    /// `WinHttpWebSocketCompleteUpgrade` — completes a WebSocket upgrade handshake.
    WinHttpWebSocketCompleteUpgrade,
    /// `WinHttpWebSocketSend` — sends data over a WebSocket connection.
    WinHttpWebSocketSend,
    /// `WinHttpWebSocketReceive` — receives data from a WebSocket connection.
    WinHttpWebSocketReceive,
    /// `WinHttpWebSocketClose` — closes a WebSocket connection.
    WinHttpWebSocketClose,
    /// `WinHttpWebSocketQueryCloseStatus` — retrieves the close status from a WebSocket closure.
    WinHttpWebSocketQueryCloseStatus,
    // -- J1: WinHTTP QueryOption & Proxy ---------------------------------------
    /// `WinHttpQueryOption` — queries an HTTP option value.
    WinHttpQueryOption,
    /// `WinHttpGetProxyForUrl` — gets the proxy for a given URL.
    WinHttpGetProxyForUrl,
    /// `WinHttpGetIEProxyConfigForCurrentUser` — retrieves the current user's proxy settings.
    WinHttpGetIEProxyConfigForCurrentUser,
    // -- J3: WinINet FTP operations --------------------------------------------
    /// `FtpGetFileW` — retrieves a file from an FTP server.
    FtpGetFileW,
    /// `FtpPutFileW` — uploads a file to an FTP server.
    FtpPutFileW,
    /// `FtpOpenFileW` — opens a remote file on an FTP server.
    FtpOpenFileW,
    /// `FtpFindFirstFileW` — finds the first file on an FTP server matching a pattern.
    FtpFindFirstFileW,
    /// `FtpDeleteFileW` — deletes a file on an FTP server.
    FtpDeleteFileW,
    /// `FtpRenameFileW` — renames a file on an FTP server.
    FtpRenameFileW,
    /// `FtpSetCurrentDirectoryW` — sets the current working directory on an FTP server.
    FtpSetCurrentDirectoryW,
    /// `FtpGetCurrentDirectoryW` — gets the current working directory on an FTP server.
    FtpGetCurrentDirectoryW,
    /// `FtpCreateDirectoryW` — creates a directory on an FTP server.
    FtpCreateDirectoryW,
    /// `FtpRemoveDirectoryW` — removes a directory on an FTP server.
    FtpRemoveDirectoryW,
    // -- Phase 1.3.3: Missing kernel32.dll imports for Steam.exe ----------------
    /// `SetFilePointerEx` — moves the file pointer of the specified file.
    SetFilePointerEx,
    /// `GetFileSizeEx` — retrieves the size of the specified file.
    GetFileSizeEx,
    /// `GetFileTime` — retrieves the date and time that a file was created, accessed, and modified.
    GetFileTime,
    /// `SetEndOfFile` — sets the physical file size for the specified file to the current position of the file pointer.
    SetEndOfFile,
    /// `SleepEx` — suspends the current thread until the condition is met (alertable sleep).
    SleepEx,
    /// `CopyFileW` — copies an existing file to a new file.
    CopyFileW,
    /// `MoveFileExW` — moves an existing file or a directory, including its children.
    MoveFileExW,
    // -- kernel32 core surface: interlocked / environment / INI / file-info /
    //    version / search / loader-lock --------------------------------------
    /// `DisableThreadLibraryCalls` — marks the module (hModule, or the
    /// calling module when NULL) so the loader skips its DLL_THREAD_ATTACH
    /// and DLL_THREAD_DETACH notifications (DllMain reasons and the
    /// matching TLS callbacks) for every later thread.  Always succeeds.
    DisableThreadLibraryCalls,
    /// `ExpandEnvironmentStringsW` — expands `%VARNAME%` references in the
    /// source string against the guest process environment; undefined
    /// variables are copied through literally.  Returns the length written
    /// (excluding the NUL) or the required size (including the NUL) when
    /// the buffer is too small, with ERROR_INSUFFICIENT_BUFFER.
    ExpandEnvironmentStringsW,
    /// `GetFileInformationByHandleEx` — FileBasicInfo class: writes the
    /// creation/last-access/last-write FILETIMEs (the same values GetFileTime
    /// reports for the handle), the change time (equal to the write time, as
    /// the runtime tracks no separate change timestamp), and the file
    /// attributes.
    GetFileInformationByHandleEx,
    /// `GetPrivateProfileStringW` — reads a section/key value from an INI
    /// document (the same storage WritePrivateProfileStringW maintains);
    /// missing sections/keys return the default string.  A NULL key name
    /// lists the section's key names (multi-string); a NULL app name lists
    /// the section names.
    GetPrivateProfileStringW,
    /// `GetVersionExA` — ANSI variant of GetVersionExW: identical version
    /// fields with the OSVERSIONINFOEXA structure layout.
    GetVersionExA,
    /// `InterlockedCompareExchange` — atomically stores `exchange` into the
    /// guest-memory 32-bit value at `destination` when it equals `comparand`;
    /// returns the previous value.
    InterlockedCompareExchange,
    /// `InterlockedDecrement` — atomically decrements the guest-memory
    /// 32-bit value at `destination`; returns the NEW value.
    InterlockedDecrement,
    /// `InterlockedExchange` — atomically stores `value` into the
    /// guest-memory 32-bit value at `destination`; returns the previous
    /// value.
    InterlockedExchange,
    /// `InterlockedExchangeAdd` — atomically adds `addend` to the
    /// guest-memory 32-bit value at `destination`; returns the previous
    /// value.
    InterlockedExchangeAdd,
    /// `InterlockedIncrement` — atomically increments the guest-memory
    /// 32-bit value at `destination`; returns the NEW value.
    InterlockedIncrement,
    /// `MoveFileW` — moves an existing file or directory (rename); the
    /// MOVEFILE_REPLACE_EXISTING=0 path of MoveFileExW, so an existing
    /// destination fails.
    MoveFileW,
    /// `SearchPathW` — resolves a file name against the DLL search path
    /// (app directory → System32 → Windows → PATH) or an explicit
    /// semicolon-separated path list; returns the found path length, the
    /// required size on a small buffer, or 0 with ERROR_FILE_NOT_FOUND.
    SearchPathW,
    /// `lstrcmpiA` — case-insensitive ordinal comparison of two ANSI
    /// strings (the case_fold machinery of lstrcmpiW over the ANSI code
    /// page); returns -1 / 0 / 1.
    LstrcmpiA,
    /// `CreateFileA` — ANSI variant of CreateFileW.
    CreateFileA,
    /// `RemoveDirectoryA` — ANSI variant of RemoveDirectoryW.
    RemoveDirectoryA,
    /// `GetFileAttributesA` — ANSI variant of GetFileAttributesW.
    GetFileAttributesA,
    /// `GetCurrentDirectoryA` — ANSI variant of GetCurrentDirectoryW.
    GetCurrentDirectoryA,
    /// `GetDriveTypeW` — determines whether a disk drive is a removable, fixed, CD-ROM, RAM disk, or network drive.
    GetDriveTypeW,
    /// `CompareStringW` — compares two character strings for a specified locale.
    CompareStringW,
    /// `GlobalMemoryStatusEx` — obtains information about the system's current usage of both physical and virtual memory.
    GlobalMemoryStatusEx,
    /// `HeapValidate` — validates the specified heap.
    HeapValidate,
    /// `HeapSetInformation` — sets heap information for the specified heap.
    HeapSetInformation,
    /// `HeapLock` — attempts to acquire the critical section of the specified heap.
    HeapLock,
    /// `HeapUnlock` — releases ownership of the critical section of the specified heap.
    HeapUnlock,
    /// `HeapWalk` — enumerates the memory blocks in the specified heap.
    HeapWalk,
    /// `HeapQueryInformation` — retrieves information about the specified heap.
    HeapQueryInformation,
    /// `IsBadWritePtr` — verifies that the calling process has write access to the specified memory range.
    IsBadWritePtr,
    /// `SwitchToThread` — causes the calling thread to yield execution to another thread.
    SwitchToThread,
    /// `OpenThread` — opens an existing thread object.
    OpenThread,
    /// `SetThreadPriority` — sets the priority value for the specified thread.
    SetThreadPriority,
    /// `ExitThread` — ends the calling thread (noreturn; the exit code is
    /// recorded and the thread never resumes).
    ExitThread,
    /// `TerminateThread` — terminates a thread.
    TerminateThread,
    /// `SuspendThread` — suspends the specified thread.
    SuspendThread,
    /// `ResumeThread` — decrements a thread's suspend count.
    ResumeThread,
    /// `SetThreadAffinityMask` — sets a processor affinity mask for the specified thread.
    SetThreadAffinityMask,
    /// `GetProcessAffinityMask` — obtains the process affinity mask for the specified process.
    GetProcessAffinityMask,
    /// `DebugBreak` — causes a breakpoint exception to occur in the current process.
    DebugBreak,
    /// `RaiseException` — raises an exception in the calling thread.
    RaiseException,
    /// `RtlUnwind` — initiates an unwind of procedure call frames.
    RtlUnwind,
    /// `RtlRestoreContext` — restores the exception context and resumes execution.
    RtlRestoreContext,
    /// `GetConsoleMode` — retrieves the current input mode of a console's input buffer or the current output mode of a console screen buffer.
    GetConsoleMode,
    /// `SetConsoleMode` — sets the input mode of a console's input buffer or the output mode of a console screen buffer.
    SetConsoleMode,
    /// `WriteConsoleW` — writes a character string to a console screen buffer.
    WriteConsoleW,
    /// `ReadConsoleA` — reads character input from the console input buffer (ANSI).
    ReadConsoleA,
    /// `ReadConsoleW` — reads character input from the console input buffer (Unicode).
    ReadConsoleW,
    /// `GetConsoleCP` — retrieves the input code page used by the console.
    GetConsoleCP,
    /// `SetStdHandle` — sets the handle for the specified standard device.
    SetStdHandle,
    /// `DeviceIoControl` — sends a control code directly to a specified device driver.
    DeviceIoControl,
    /// `SetProcessAffinityMask` — sets a processor affinity mask for the threads of the specified process.
    SetProcessAffinityMask,
    /// `InterlockedPushEntrySList` — inserts an item at the front of a singly linked list.
    InterlockedPushEntrySList,
    /// `FindResourceA` — determines the location of a resource with the specified type and name (ANSI).
    FindResourceA,
    /// `SizeofResource` — retrieves the size, in bytes, of the specified resource.
    SizeofResource,
    /// `LoadResource` — retrieves a handle that can be used to obtain a pointer to the first byte of the specified resource in memory.
    LoadResource,
    /// `LockResource` — retrieves a pointer to the specified resource in memory.
    LockResource,
    /// `SystemTimeToFileTime` — converts a system time to a file time.
    SystemTimeToFileTime,
    /// `GetSystemTime` — retrieves the current system date and time in UTC.
    GetSystemTime,
    /// `FileTimeToSystemTime` — converts a file time to system time format.
    FileTimeToSystemTime,
    /// `SystemTimeToTzSpecificLocalTime` — converts a system time to a specified time zone's local time.
    SystemTimeToTzSpecificLocalTime,
    /// `GetDateFormatW` — formats a date as a date string for a specified locale.
    GetDateFormatW,
    /// `GetTimeFormatW` — formats a time as a time string for a specified locale.
    GetTimeFormatW,
    /// `WaitForSingleObjectEx` — waits until the specified object is in the signaled state or the time-out interval elapses (alertable).
    WaitForSingleObjectEx,
    /// `FindFirstFileExW` — searches a directory for a file or subdirectory whose name and attributes match those specified.
    FindFirstFileExW,
    /// `GetDiskFreeSpaceA` — ANSI variant of GetDiskFreeSpaceW.
    GetDiskFreeSpaceA,
    /// `SetConsoleCtrlHandler` — adds or removes an application-defined HandlerRoutine function.
    SetConsoleCtrlHandler,
    GenerateConsoleCtrlEvent,
    /// `ConvertThreadToFiber` — converts the current thread into a fiber.
    ConvertThreadToFiber,
    /// `ConvertFiberToThread` — converts the current fiber into a thread.
    ConvertFiberToThread,
    /// `CreateFiber` — allocates a fiber object, assigns it a stack, and sets up execution to begin at the specified start address.
    CreateFiber,
    /// `DeleteFiber` — deletes an existing fiber.
    DeleteFiber,
    /// `SwitchToFiber` — schedules a fiber.
    SwitchToFiber,
    // -- Phase M4: SxS Activation Context API (kernel32.dll) ---------------------
    /// `CreateActCtxW` — creates an activation context.
    CreateActCtxW,
    /// `ActivateActCtx` — activates the specified activation context.
    ActivateActCtx,
    /// `DeactivateActCtx` — deactivates the specified activation context.
    DeactivateActCtx,
    /// `ReleaseActCtx` — releases an activation context.
    ReleaseActCtx,
    /// `FindActCtxSectionStringW` — finds a string in an activation context section.
    FindActCtxSectionStringW,
    // -- Phase 1.3.3: Missing user32.dll imports for Steam.exe ------------------
    /// `GetWindowThreadProcessId` — retrieves the identifier of the thread that created the specified window.
    GetWindowThreadProcessId,
    /// `KillTimer` — destroys the specified timer.
    KillTimer,
    /// `MoveWindow` — changes the position and dimensions of the specified window.
    MoveWindow,
    /// `GetDesktopWindow` — retrieves a handle to the desktop window.
    GetDesktopWindow,
    /// `MsgWaitForMultipleObjects` — waits until one or all of the specified objects are in the signaled state, an I/O completion routine or APC is queued, or the time-out interval elapses.
    MsgWaitForMultipleObjects,
    /// `UpdateWindow` — updates the client area of the specified window.
    UpdateWindow,
    /// `UnregisterClassW` — unregisters a window class, freeing the memory required for the class.
    UnregisterClassW,
    /// `wsprintfA` — ANSI variant of wsprintfW.
    WsprintfA,
    /// `DialogBoxParamA` — ANSI variant of DialogBoxParamW.
    DialogBoxParamA,
    /// `SetDlgItemInt` — sets the text of a control in a dialog box to the string representation of a specified integer value.
    SetDlgItemInt,
    /// `GetDlgItemInt` — translates the text of a specified control in a dialog box into an integer value.
    GetDlgItemInt,
    /// `SetDlgItemTextA` — ANSI variant of SetDlgItemTextW.
    SetDlgItemTextA,
    /// `IsDialogMessageW` — determines whether a message is intended for a dialog box and, if so, processes it.
    IsDialogMessageW,
    /// `SendDlgItemMessageW` — sends a message to a specified control in a dialog box.
    SendDlgItemMessageW,
    /// `DefDlgProcW` — default dialog window procedure.
    DefDlgProcW,
    /// `OpenClipboard` — opens the clipboard for examination.
    OpenClipboard,
    /// `CloseClipboard` — closes the clipboard.
    CloseClipboard,
    /// `SetClipboardData` — places data on the clipboard in a specified clipboard format.
    SetClipboardData,
    /// `EmptyClipboard` — empties the clipboard and frees handles to data in the clipboard.
    EmptyClipboard,
    /// `GetClipboardData` — retrieves data from the clipboard in a specified format.
    GetClipboardData,
    /// `IsClipboardFormatAvailable` — determines whether the clipboard contains data in the specified format.
    IsClipboardFormatAvailable,
    /// `EnumClipboardFormats` — enumerates the data formats currently available on the clipboard.
    EnumClipboardFormats,
    /// `GetWindowTextLengthA` — retrieves the length of the specified window's title bar text (ANSI).
    GetWindowTextLengthA,
    /// `GetProcessWindowStation` — retrieves a handle to the current window station.
    GetProcessWindowStation,
    /// `EnumWindows` — enumerates all top-level windows.
    EnumWindows,
    /// `MonitorFromPoint` — retrieves a handle to the display monitor that contains a specified point.
    MonitorFromPoint,
    /// `EnumChildWindows` — enumerates the child windows that belong to the specified parent window.
    EnumChildWindows,
    /// `MapWindowPoints` — converts (maps) a set of points from a coordinate space relative to one window to a coordinate space relative to another window.
    MapWindowPoints,
    /// `GetUserObjectInformationW` — retrieves information about a window station or desktop object.
    GetUserObjectInformationW,
    /// `AllowSetForegroundWindow` — enables the specified process to set the foreground window.
    AllowSetForegroundWindow,
    /// `MessageBoxA` — ANSI variant of MessageBoxW.
    MessageBoxA,
    // -- Phase 1.3.3: Missing gdi32.dll imports for Steam.exe -------------------
    /// `AddFontMemResourceEx` — adds an embedded font to the system font table.
    AddFontMemResourceEx,
    /// `RemoveFontMemResourceEx` — removes a font whose source was embedded in a document from the system font table.
    RemoveFontMemResourceEx,
    /// `TextOutW` — writes a character string at the specified location.
    TextOutW,
    /// `CreateDIBSection` — creates a DIB that applications can write to directly.
    CreateDIBSection,
    /// `DeleteDC` — deletes the specified device context.
    DeleteDC,
    /// `CreateICW` — creates an information context for the specified device (Unicode).
    CreateICW,
    /// `CreateCompatibleDC` — creates a memory device context compatible with the specified device.
    CreateCompatibleDC,
    /// `SwapBuffers` — swaps the front and back buffers of a double-buffered pixel format.
    SwapBuffers,
    /// `SetPixelFormat` — sets the pixel format of the specified device context.
    SetPixelFormat,
    /// `ChoosePixelFormat` — attempts to match an appropriate pixel format supported by a device context to a given pixel format specification.
    ChoosePixelFormat,
    // -- Phase 1.3.3: Missing advapi32.dll imports for Steam.exe ----------------
    /// `RegisterEventSourceW` — retrieves a registered handle to the specified event log.
    RegisterEventSourceW,
    /// `DeregisterEventSource` — closes a write handle to the specified event log.
    DeregisterEventSource,
    /// `ReportEventW` — writes an entry at the end of the specified event log.
    ReportEventW,
    // -- Phase 1.3.3: Missing psapi.dll imports for Steam.exe -------------------
    /// `GetModuleFileNameExW` — retrieves the fully qualified path for the specified module.
    GetModuleFileNameExW,
    /// `GetModuleInformation` — retrieves information about the specified module.
    GetModuleInformation,
    /// `GetProcessMemoryInfo` — retrieves information about the memory usage of the specified process.
    GetProcessMemoryInfo,
    // -- setupapi.dll: device-info-set surface --------------------------------
    /// `SetupDiGetClassDevsW` — builds a device information set for the
    /// devices matching the given class GUID / enumerator / device instance
    /// path.  The device list is backed by the guest registry's device
    /// enumeration (`HKLM\SYSTEM\CurrentControlSet\Enum`); returns an
    /// HDEVINFO handle for the device-info-set, or INVALID_HANDLE_VALUE +
    /// ERROR_INVALID_PARAMETER for an unknown class GUID.
    SetupDiGetClassDevsW,
    /// `SetupDiDestroyDeviceInfoList` — frees a device information set.
    SetupDiDestroyDeviceInfoList,
    /// `SetupDiEnumDeviceInfo` — enumerates the device information elements
    /// in a device information set; returns FALSE + ERROR_NO_MORE_ITEMS when
    /// the index is past the end of the list.
    SetupDiEnumDeviceInfo,
    /// `SetupDiGetDeviceInstanceIdW` — retrieves the device instance ID
    /// (e.g. `ROOT\SYSTEM\0000`) of a device information element.
    SetupDiGetDeviceInstanceIdW,
    /// `SetupDiGetDeviceRegistryPropertyW` — reads a device property value
    /// from the device's guest-registry key under `HKLM\SYSTEM\
    /// CurrentControlSet\Enum\<device instance ID>`.
    SetupDiGetDeviceRegistryPropertyW,
    /// `SetupDiOpenDeviceInfoW` — opens an existing device information
    /// element for the given device instance ID.
    SetupDiOpenDeviceInfoW,
    /// `SetupDiSetDeviceRegistryPropertyW` — writes a device property value
    /// into the device's guest-registry key.
    SetupDiSetDeviceRegistryPropertyW,
    /// `SetupDiCallClassInstaller` — invokes the default class installer
    /// behavior for a DIF code; the default-installer codes are handled
    /// (success) and unhandled codes fail honestly with
    /// ERROR_INVALID_PARAMETER.
    SetupDiCallClassInstaller,
    /// `SetupDiGetClassDescriptionW` — retrieves the class description for a
    /// class GUID from the guest registry's class database
    /// (`HKLM\SYSTEM\CurrentControlSet\Control\Class\<GUID>`).
    SetupDiGetClassDescriptionW,
    /// `SetupDiBuildDriverInfoList` — builds a list of drivers for a device;
    /// with an empty guest driver database the list is empty and the call
    /// succeeds.
    SetupDiBuildDriverInfoList,
    /// `SetupDiDestroyDriverInfoList` — frees a driver information list.
    SetupDiDestroyDriverInfoList,
    /// `SetupDiEnumDriverInfoW` — enumerates the driver information elements
    /// of a device's driver list; returns FALSE + ERROR_NO_MORE_ITEMS when
    /// the list is exhausted (or was never built).
    SetupDiEnumDriverInfoW,
    /// `SetupDiGetSelectedDriverW` — retrieves the selected driver of a
    /// device; fails with ERROR_NO_DEVICE_SELECTED when no driver has been
    /// selected (the honest documented error for an empty driver list).
    SetupDiGetSelectedDriverW,
    /// `SetupDiInstallDevice` — installs a device through the default
    /// installer: marks the device installed in its guest-registry key and
    /// returns success.
    SetupDiInstallDevice,
    /// `SetupDiUninstallDevice` — uninstalls a device: marks the device
    /// uninstalled in its guest-registry key and returns success.
    SetupDiUninstallDevice,
    // -- Phase 1.3.3: Missing bcrypt.dll imports for Steam.exe ------------------
    /// `BCryptGenRandom` — generates a random number.
    BCryptGenRandom,
    // -- Phase O1: Full BCrypt algorithm suite (18 functions) --------------------
    /// `BCryptOpenAlgorithmProvider` — opens an algorithm provider.
    BCryptOpenAlgorithmProvider,
    /// `BCryptCloseAlgorithmProvider` — closes an algorithm provider.
    BCryptCloseAlgorithmProvider,
    /// `BCryptGenerateSymmetricKey` — creates a symmetric key from a key blob.
    BCryptGenerateSymmetricKey,
    /// `BCryptGenerateKeyPair` — creates an asymmetric key pair.
    BCryptGenerateKeyPair,
    /// `BCryptFinalizeKeyPair` — finalizes a key pair.
    BCryptFinalizeKeyPair,
    /// `BCryptEncrypt` — encrypts data.
    BCryptEncrypt,
    /// `BCryptDecrypt` — decrypts data.
    BCryptDecrypt,
    /// `BCryptHash` — one-shot hash operation.
    BCryptHash,
    /// `BCryptHashData` — adds data to an incremental hash.
    BCryptHashData,
    /// `BCryptCreateHash` — creates a hash object.
    BCryptCreateHash,
    /// `BCryptDestroyHash` — destroys a hash object.
    BCryptDestroyHash,
    /// `BCryptDestroyKey` — destroys a key handle.
    BCryptDestroyKey,
    /// `BCryptGetProperty` — queries a property of a CNG object.
    BCryptGetProperty,
    /// `BCryptSetProperty` — sets a property of a CNG object.
    BCryptSetProperty,
    /// `BCryptDeriveKey` — derives a key from a secret agreement.
    BCryptDeriveKey,
    /// `BCryptSecretAgreement` — performs a secret agreement (ECDH).
    BCryptSecretAgreement,
    /// `BCryptImportKey` — imports a key from a key blob.
    BCryptImportKey,
    /// `BCryptSignHash` — signs a hash value.
    BCryptSignHash,
    /// `BCryptVerifySignature` — verifies a signature.
    BCryptVerifySignature,
    // -- Phase 1.3.3: Missing crypt32.dll imports for Steam.exe -----------------
    /// `CertOpenStore` — opens a certificate store.
    CertOpenStore,
    /// `CertCloseStore` — closes a certificate store.
    CertCloseStore,
    /// `CertGetCertificateChain` — builds a certificate chain context starting from an end certificate.
    CertGetCertificateChain,
    /// `CertCreateCertificateContext` — creates a certificate context from an encoded certificate.
    CertCreateCertificateContext,
    /// `CertFreeCertificateContext` — frees a certificate context.
    CertFreeCertificateContext,
    /// `CertAddCertificateContextToStore` — adds a certificate context to a certificate store.
    CertAddCertificateContextToStore,
    /// `CertFreeCertificateChain` — frees a certificate chain.
    CertFreeCertificateChain,
    // -- Phase O2: Extended crypt32.dll certificate store management ------------------
    /// `CertOpenSystemStoreW` — opens a system certificate store.
    CertOpenSystemStoreW,
    /// `CertFindCertificateInStore` — finds certificates in a store.
    CertFindCertificateInStore,
    /// `CertGetNameStringW` — gets a certificate name string.
    CertGetNameStringW,
    /// `CertDuplicateCertificateContext` — duplicates a certificate context.
    CertDuplicateCertificateContext,
    /// `CertVerifyCertificateChainPolicy` — verifies a certificate chain policy.
    CertVerifyCertificateChainPolicy,
    /// `CertEnumCertificatesInStore` — enumerates certificates in a store.
    CertEnumCertificatesInStore,
    /// `CertDeleteCertificateFromStore` — deletes a certificate from a store.
    CertDeleteCertificateFromStore,
    /// `CryptAcquireCertificatePrivateKey` — acquires a private key for a certificate.
    CryptAcquireCertificatePrivateKey,
    /// `PFXImportCertStore` — imports a PFX/PKCS#12 blob as a certificate store.
    PFXImportCertStore,
    /// `PFXIsPFXBlob` — checks if a blob is a PFX/PKCS#12 blob.
    PFXIsPFXBlob,
    /// `CertFindExtension` — finds an extension in a certificate by OID.
    CertFindExtension,
    /// `CertGetIntendedKeyUsage` — gets the intended key usage from a certificate.
    CertGetIntendedKeyUsage,
    // -- Phase 2.1: CEF (libcef.dll) exports for Steam UI --------------------------
    /// `cef_initialize` — initialise the CEF subsystem (maps to CefBridge::cef_initialize)
    CefInitialize,
    /// `cef_shutdown` — shut down the CEF subsystem (maps to CefBridge::cef_shutdown)
    CefShutdown,
    /// `cef_get_minimal_libcef_version` — returns the minimum required libcef version
    CefGetMinimalLibcefVersion,
    /// `cef_browser_host_create_browser` — create a new browser instance
    CefBrowserHostCreateBrowser,
    /// `cef_browser_host_create_browser_sync` — create a browser synchronously
    CefBrowserHostCreateBrowserSync,
    /// `cef_browser_get_host` — get the browser host from a browser handle
    CefBrowserGetHost,
    /// `cef_browser_get_main_frame` — get the main frame from a browser handle
    CefBrowserGetMainFrame,
    /// `cef_browser_is_valid` — check if a browser handle is valid
    CefBrowserIsValid,
    /// `cef_frame_load_url` — navigate a frame to a URL
    CefFrameLoadUrl,
    /// `cef_frame_load_string` — load a string as page content in a frame
    CefFrameLoadString,
    /// `cef_browser_go_back` — navigate back in browser history
    CefBrowserGoBack,
    /// `cef_browser_go_forward` — navigate forward in browser history
    CefBrowserGoForward,
    /// `cef_browser_reload` — reload the current page
    CefBrowserReload,
    /// `cef_browser_reload_ignore_cache` — reload ignoring cache
    CefBrowserReloadIgnoreCache,
    /// `cef_browser_stop_load` — stop the current page load
    CefBrowserStopLoad,
    /// `cef_frame_execute_java_script` — execute JavaScript in a frame
    CefFrameExecuteJavaScript,
    /// `cef_run_message_loop` — run one iteration of the CEF message loop
    CefRunMessageLoop,
    /// `cef_do_message_loop_work` — perform one unit of message loop work
    CefDoMessageLoopWork,
    /// `cef_quit_message_loop` — quit the CEF message loop
    CefQuitMessageLoop,
    /// `cef_window_info_create` — create a CefWindowInfo struct
    CefWindowInfoCreate,
    /// `cef_browser_settings_create` — create a CefBrowserSettings struct
    CefBrowserSettingsCreate,
    /// `cef_string_utf8_to_utf16` — convert UTF-8 to UTF-16
    CefStringUtf8ToUtf16,
    /// `cef_string_utf16_to_utf8` — convert UTF-16 to UTF-8
    CefStringUtf16ToUtf8,
    /// `cef_string_utf8_to_wide` — convert UTF-8 to wide string
    CefStringUtf8ToWide,
    /// `cef_string_wide_to_utf8` — convert wide string to UTF-8
    CefStringWideToUtf8,
    /// `cef_add_cross_origin_whitelist_entry` — add a cross-origin whitelist entry
    CefAddCrossOriginWhitelistEntry,
    /// `cef_remove_cross_origin_whitelist_entry` — remove a cross-origin whitelist entry
    CefRemoveCrossOriginWhitelistEntry,
    /// `cef_clear_cross_origin_whitelist` — clear the cross-origin whitelist
    CefClearCrossOriginWhitelist,
    /// `cef_parse_url` — parse a URL string into components
    CefParseUrl,
    /// `cef_create_url` — create a URL string from components
    CefCreateUrl,
    /// `cef_register_extension` — register a V8 JavaScript extension
    CefRegisterExtension,
    /// `cef_cookie_manager_get_global` — get the global cookie manager
    CefCookieManagerGetGlobal,
    /// `cef_cookie_manager_set_supported_schemes` — set supported cookie schemes
    CefCookieManagerSetSupportedSchemes,
    /// `cef_cookie_manager_set_cookie` — set a cookie
    CefCookieManagerSetCookie,
    /// `cef_cookie_manager_visit_all_cookies` — visit all cookies
    CefCookieManagerVisitAllCookies,
    /// `cef_cookie_manager_delete_cookies` — delete cookies
    CefCookieManagerDeleteCookies,
    /// `cef_cookie_manager_flush_store` — flush the cookie store to disk
    CefCookieManagerFlushStore,
    // -- Phase 4.4: Complete synchronization primitives ----------------------
    /// `CreateMutexW` — creates or opens a named or unnamed mutex (Unicode).
    CreateMutexW,
    /// `CreateMutexA` — creates or opens a named or unnamed mutex (ANSI).
    CreateMutexA,
    /// `OpenMutexW` — opens an existing named mutex (Unicode).
    OpenMutexW,
    /// `ReleaseMutex` — releases ownership of a mutex.
    ReleaseMutex,
    /// `CreateSemaphoreW` — creates or opens a named or unnamed semaphore (Unicode).
    CreateSemaphoreW,
    /// `CreateSemaphoreA` — creates or opens a named or unnamed semaphore (ANSI).
    CreateSemaphoreA,
    /// `OpenSemaphoreW` — opens an existing named semaphore (Unicode).
    OpenSemaphoreW,
    /// `ReleaseSemaphore` — increases a semaphore's count.
    ReleaseSemaphore,
    /// `PulseEvent` — pulses an event (sets then resets, waking waiters).
    PulseEvent,
    /// `InitializeConditionVariable` — initializes a condition variable.
    InitializeConditionVariable,
    /// `WakeConditionVariable` — wakes a single waiter on a condition variable.
    WakeConditionVariable,
    /// `GetThreadPriority` — returns the priority of a thread.
    GetThreadPriority,
    /// `GetThreadTimes` — returns creation/exit/kernel/user times for a thread.
    GetThreadTimes,
    /// `CreateRemoteThread` — creates a thread in another process.
    CreateRemoteThread,
    /// `QueueUserAPC` — queues an APC to a thread's APC queue.
    QueueUserAPC,
    // -- Phase 4.4: Thread pool APIs -------------------------------------------
    /// `QueueUserWorkItem` — queues a work item to the thread pool.
    QueueUserWorkItem,
    /// `CreateThreadpoolWork` — creates a work object.
    CreateThreadpoolWork,
    /// `SubmitThreadpoolWork` — submits a work object to the pool.
    SubmitThreadpoolWork,
    /// `WaitForThreadpoolWorkCallbacks` — waits for pending work callbacks.
    WaitForThreadpoolWorkCallbacks,
    /// `CloseThreadpoolWork` — closes a work object.
    CloseThreadpoolWork,
    /// `CreateThreadpoolTimer` — creates a timer object.
    CreateThreadpoolTimer,
    /// `SetThreadpoolTimer` — sets a timer object.
    SetThreadpoolTimer,
    /// `CloseThreadpoolTimer` — closes a timer object.
    CloseThreadpoolTimer,
    /// `CreateThreadpoolWait` — creates a wait object.
    CreateThreadpoolWait,
    /// `SetThreadpoolWait` — sets a wait object.
    SetThreadpoolWait,
    /// `CloseThreadpoolWait` — closes a wait object.
    CloseThreadpoolWait,
    // -- Phase N2: Timer Queue & Wait Registration --------------------------------
    /// `CreateTimerQueueTimer` — creates a timer-queue timer.
    CreateTimerQueueTimer,
    /// `DeleteTimerQueueTimer` — deletes a timer-queue timer.
    DeleteTimerQueueTimer,
    /// `RegisterWaitForSingleObject` — registers a wait on a handle.
    RegisterWaitForSingleObject,
    /// `UnregisterWaitEx` — unregisters a wait registered by RegisterWaitForSingleObject.
    UnregisterWaitEx,
    // -- COM / OLE Automation (Phase P0.1) ------------------------------------
    /// `CoGetClassObject` — retrieves a class factory for a given CLSID.
    CoGetClassObject,
    /// `CoRegisterClassObject` — registers a class factory with COM.
    CoRegisterClassObject,
    /// `CoRevokeClassObject` — revokes a class factory registration.
    CoRevokeClassObject,
    /// `CoCreateInstanceEx` — creates a COM object with extended options.
    CoCreateInstanceEx,
    /// `CoCreateGuid` — creates a GUID.
    CoCreateGuid,
    /// `IClassFactory::CreateInstance` vtable thunk.
    ComFactoryCreateInstance,
    /// `IClassFactory::LockServer` vtable thunk.
    ComFactoryLockServer,
    /// `IDispatch::GetIDsOfNames` vtable thunk.
    ComDispatchGetIDsOfNames,
    /// `IDispatch::Invoke` vtable thunk.
    ComDispatchInvoke,
    /// A COM interface method dispatched through a runtime COM vtable
    /// (IStream/IStorage/IConnectionPoint/IDispatch/ITypeInfo/...).  The
    /// payload identifies the method and its ABI argument set; the
    /// implementation lives in `runtime::dispatch::com`.
    ComMethod(ComMethod),
    /// `SysAllocString` — allocates a BSTR.
    SysAllocString,
    /// `SysReAllocString` — re-allocates a BSTR.
    SysReAllocString,
    /// `SysFreeString` — frees a BSTR.
    SysFreeString,
    /// `SysAllocStringLen` — allocates a BSTR with a specified length.
    SysAllocStringLen,
    /// `SysStringLen` — returns the length of a BSTR.
    SysStringLen,
    /// `VariantInit` — initializes a VARIANT.
    VariantInit,
    /// `VariantCopy` — copies a VARIANT.
    VariantCopy,
    /// `VariantChangeType` — changes the type of a VARIANT.
    VariantChangeType,
    /// `SafeArrayCreate` — creates a SAFEARRAY.
    SafeArrayCreate,
    /// `SafeArrayDestroy` — destroys a SAFEARRAY.
    SafeArrayDestroy,
    /// `SafeArrayAccessData` — accesses SAFEARRAY data.
    SafeArrayAccessData,
    /// `SafeArrayUnaccessData` — releases access to SAFEARRAY data.
    SafeArrayUnaccessData,
    /// `SafeArrayGetElement` — gets an element from a SAFEARRAY.
    SafeArrayGetElement,
    /// `SafeArrayPutElement` — puts an element into a SAFEARRAY.
    SafeArrayPutElement,
    /// `SafeArrayGetLBound` — gets the lower bound of a SAFEARRAY dimension.
    SafeArrayGetLBound,
    /// `SafeArrayGetUBound` — gets the upper bound of a SAFEARRAY dimension.
    SafeArrayGetUBound,
    /// `SafeArrayCreateVector` — creates a one-dimensional SAFEARRAY (vector).
    SafeArrayCreateVector,
    // -- Touch / Pointer Input (Phase 6.x) --
    RegisterTouchWindow,
    UnregisterTouchWindow,
    GetTouchInputInfo,
    CloseTouchInputHandle,
    /// `InitializeTouchInjection` — configures touch injection for the window.
    /// Maps to [`User32::initialize_touch_injection`].
    InitializeTouchInjection,
    InitializePointerDevice,
    GetPointerInfo,
    GetPointerPenInfo,
    SkipPointerFrame,
    /// GetPointerDeviceCaps — retrieves pointer device capabilities.
    GetPointerDeviceCaps,
    /// GetPointerDeviceRects — gets the device and display rects.
    GetPointerDeviceRects,
    /// GetPointerFrameInfo — retrieves information about the current pointer frame.
    GetPointerFrameInfo,
    // ── Phase 2.7: GDI+ (gdiplus.dll) ——————————————————————————————————
    GdiplusStartup,
    GdiplusShutdown,
    GdipCreateFromHDC,
    GdipDeleteGraphics,
    // Drawing primitives
    GdipDrawLine,
    GdipDrawLines,
    GdipDrawRectangle,
    GdipFillRectangle,
    GdipDrawEllipse,
    GdipFillEllipse,
    GdipDrawPie,
    GdipFillPie,
    GdipDrawPolygon,
    GdipFillPolygon,
    GdipDrawArc,
    GdipDrawCurve,
    GdipDrawClosedCurve,
    GdipDrawString,
    // Brushes
    GdipCreateSolidFill,
    GdipCreateLineBrush,
    GdipCreateTextureBrush,
    GdipDeleteBrush,
    GdipFillRegion,
    // Pens
    GdipCreatePen1,
    GdipCreatePen2,
    GdipSetPenWidth,
    GdipGetPenWidth,
    GdipSetPenColor,
    GdipGetPenColor,
    GdipSetPenDashStyle,
    GdipGetPenDashStyle,
    GdipSetPenLineJoin,
    GdipSetPenStartCap,
    GdipSetPenEndCap,
    GdipDeletePen,
    // Paths
    GdipCreatePath,
    GdipDeletePath,
    GdipAddPathLine,
    GdipAddPathRectangle,
    GdipAddPathEllipse,
    GdipAddPathArc,
    GdipAddPathBezier,
    GdipClosePathFigure,
    GdipStartPathFigure,
    GdipSetPathFillMode,
    GdipDrawPath,
    GdipFillPath,
    // Transforms
    GdipCreateMatrix,
    GdipDeleteMatrix,
    GdipSetMatrixElements,
    GdipGetMatrixElements,
    GdipTranslateMatrix,
    GdipRotateMatrix,
    GdipScaleMatrix,
    GdipInvertMatrix,
    GdipMultiplyMatrix,
    GdipSetWorldTransform,
    GdipResetWorldTransform,
    GdipGetWorldTransform,
    // Clipping
    GdipSetClipRect,
    GdipSetClipPath,
    GdipSetClipRegion,
    GdipResetClip,
    GdipGetClipBounds,
    GdipGetClip,
    // Containers
    GdipSaveGraphics,
    GdipRestoreGraphics,
    GdipBeginContainer,
    GdipEndContainer,
    // Bitmap interop
    GdipCreateBitmapFromHBITMAP,
    GdipCreateBitmapFromFile,
    GdipCreateBitmapFromGraphics,
    GdipDisposeImage,
    GdipGetImageWidth,
    GdipGetImageHeight,
    GdipGetImagePixelFormat,
    GdipBitmapGetPixel,
    GdipBitmapSetPixel,
    GdipBitmapLockBits,
    GdipBitmapUnlockBits,
    // Text/Font
    GdipCreateFont,
    GdipDeleteFont,
    GdipCreateFontFamilyFromName,
    GdipDeleteFontFamily,
    GdipSetTextRenderingHint,
    GdipMeasureString,
    GdipMeasureCharacterRanges,
    // Image attributes
    GdipCreateImageAttributes,
    GdipDisposeImageAttributes,
    GdipSetImageAttributesColorKeys,
    GdipSetImageAttributesColorMatrix,
    // Quality settings
    GdipSetSmoothingMode,
    GdipGetSmoothingMode,
    GdipSetCompositingMode,
    GdipGetCompositingMode,
    GdipSetCompositingQuality,
    GdipGetCompositingQuality,
    GdipSetInterpolationMode,
    GdipGetInterpolationMode,
    GdipSetPixelOffsetMode,
    GdipGetPixelOffsetMode,
    // Image drawing
    GdipDrawImage,
    GdipDrawImageRect,
    GdipDrawImageRectRect,
    GdipGetImageType,
    GdipGetImageRawFormat,
    GdipCloneImage,
    GdipSaveImageToFile,
    GdipSaveImageToStream,
    GdipCreateBitmapFromStream,
    GdipCreateBitmapFromScan0,
    GdipCreateHICONFromBitmap,
    GdipCreateHBITMAPFromBitmap,
    GdipCreateImageFromFile,
    GdipImageForceValidation,
    GdipGetFontHeight,
    GdipCreateBitmapFromGdiDib,
    // ── WMI (Windows Management Instrumentation) ───────────────────────────────
    /// IWbemLocator::ConnectServer
    WbemLocatorConnectServer,
    /// IWbemServices::ExecQuery
    WbemServicesExecQuery,
    /// IWbemServices::CreateInstanceEnum
    WbemServicesCreateInstanceEnum,
    /// IWbemServices::GetObject
    WbemServicesGetObject,
    /// IWbemClassObject::Get
    WbemClassObjectGet,
    /// IWbemClassObject::Put
    WbemClassObjectPut,
    /// IWbemClassObject::GetNames
    WbemClassObjectGetNames,
    /// IWbemClassObject::GetObjectText
    WbemClassObjectGetObjectText,
    /// IEnumWbemClassObject::Next
    EnumWbemClassObjectNext,
    /// IEnumWbemClassObject::Reset
    EnumWbemClassObjectReset,
    /// IEnumWbemClassObject::Skip
    EnumWbemClassObjectSkip,
    /// IEnumWbemClassObject::Clone
    EnumWbemClassObjectClone,
    /// A native function from a real (on-disk) DLL loaded via `load_real_dll`.
    /// When dispatched, the runtime looks up the loaded native library for this
    /// DLL and calls the native function pointer.
    RealDllExport {
        dll_name: String,
        export_name: String,
    },
    // ── WebView2 (webview2.dll) ───────────────────────────────────────────────
    /// `CreateWebView2Environment` — entry point into WebView2.
    WebView2CreateEnvironment,
    /// `CreateWebView2EnvironmentWithDetails` — entry point with detailed options.
    WebView2CreateEnvironmentWithDetails,
    // ICoreWebView2Environment vtable
    WebView2EnvRelease,
    WebView2EnvCreateCoreWebView2Controller,
    WebView2EnvCreateWebResourceResponse,
    WebView2EnvGetBrowserVersionString,
    // ICoreWebView2Controller vtable
    WebView2CtrlRelease,
    WebView2CtrlGetIsVisible,
    WebView2CtrlPutIsVisible,
    WebView2CtrlGetBounds,
    WebView2CtrlPutBounds,
    WebView2CtrlGetZoomFactor,
    WebView2CtrlPutZoomFactor,
    WebView2CtrlMoveFocus,
    WebView2CtrlClose,
    WebView2CtrlGetCoreWebView2,
    // ICoreWebView2 vtable
    WebView2Release,
    WebView2GetSource,
    WebView2Navigate,
    WebView2NavigateToString,
    WebView2ExecuteScript,
    WebView2PostWebMessageAsJson,
    WebView2PostWebMessageAsString,
    WebView2GetSettings,
    WebView2AddNavigationStarting,
    WebView2RemoveNavigationStarting,
    WebView2AddNavigationCompleted,
    WebView2RemoveNavigationCompleted,
    WebView2AddWebMessageReceived,
    WebView2RemoveWebMessageReceived,
    WebView2Stop,
    WebView2Reload,
    WebView2CallDevToolsProtocolMethod,
    // ICoreWebView2_2
    WebView2AddContentLoading,
    WebView2RemoveContentLoading,
    WebView2AddSourceChanged,
    WebView2RemoveSourceChanged,
    WebView2AddHistoryChanged,
    WebView2RemoveHistoryChanged,
    // ICoreWebView2_3
    WebView2AddNewWindowRequested,
    WebView2RemoveNewWindowRequested,
    WebView2AddPermissionRequested,
    WebView2RemovePermissionRequested,
    WebView2AddProcessFailed,
    WebView2RemoveProcessFailed,
    // ICoreWebView2_4
    WebView2AddDownloadStarting,
    WebView2RemoveDownloadStarting,
    // ICoreWebView2Settings vtable
    WebView2SettingsRelease,
    WebView2SettingsGetIsScriptEnabled,
    WebView2SettingsPutIsScriptEnabled,
    WebView2SettingsGetIsWebMessageEnabled,
    WebView2SettingsPutIsWebMessageEnabled,
    WebView2SettingsGetIsStatusBarEnabled,
    WebView2SettingsPutIsStatusBarEnabled,
    WebView2SettingsGetAreDevToolsEnabled,
    WebView2SettingsPutAreDevToolsEnabled,
    WebView2SettingsGetDefaultBackgroundColor,
    WebView2SettingsPutDefaultBackgroundColor,
    WebView2SettingsGetIsBuiltInErrorPageEnabled,
    WebView2SettingsPutIsBuiltInErrorPageEnabled,
    // ICoreWebView2WebResourceResponse vtable
    WebView2WebResourceResponseRelease,
    // -- D2D helper functions (D2D1.DLL) --
    D2D1MakeRotateMatrix,
    D2D1MakeSkewMatrix,
    D2D1IsMatrixInvertible,
    D2D1InvertMatrix,
    // -- WinMM (Windows Multimedia) audio (Phase 2.5) --
    WaveOutOpen,
    WaveOutClose,
    WaveOutPrepareHeader,
    WaveOutUnprepareHeader,
    WaveOutWrite,
    WaveOutReset,
    WaveOutGetVolume,
    WaveOutSetVolume,
    WaveOutGetDevCapsW,
    WaveOutGetNumDevs,
    WaveInOpen,
    WaveInClose,
    WaveInPrepareHeader,
    WaveInUnprepareHeader,
    WaveInAddBuffer,
    WaveInStart,
    WaveInStop,
    WaveInGetDevCapsW,
    WaveInGetNumDevs,
    MidiOutOpen,
    MidiOutClose,
    MidiOutShortMsg,
    MidiOutLongMsg,
    MidiOutReset,
    MidiOutGetDevCapsW,
    MidiOutGetNumDevs,
    MidiInOpen,
    MidiInClose,
    MidiInStart,
    MidiInStop,
    MidiInReset,
    TimeGetTime,
    TimeBeginPeriod,
    TimeEndPeriod,
    PlaySoundW,
    MmioOpenW,
    MmioClose,
    MmioRead,
    MmioWrite,
    MmioAscend,
    MmioDescend,
    MmioCreateChunk,
    MmioStringToFOURCCW,
    // ── advapi32: access tokens (mid-size families) ────────────────────
    /// `AdjustTokenPrivileges` — enable/disable privileges in a token.
    AdjustTokenPrivileges,
    /// `AllocateAndInitializeSid` — build a SID from subauthorities.
    AllocateAndInitializeSid,
    /// `CheckTokenMembership` — test a SID against the token's SIDs.
    CheckTokenMembership,
    /// `DuplicateTokenEx` — duplicate a token with a new access/level.
    DuplicateTokenEx,
    /// `FreeSid` — free a SID allocated by AllocateAndInitializeSid.
    FreeSid,
    /// `GetTokenInformation` — the documented TOKEN_INFORMATION_CLASSes.
    GetTokenInformation,
    /// `ImpersonateLoggedOnUser` — attach the token as the thread token.
    ImpersonateLoggedOnUser,
    /// `LookupPrivilegeValueW` — the documented privilege LUID constants.
    LookupPrivilegeValueW,
    /// `OpenProcessToken` — open the process token.
    OpenProcessToken,
    /// `OpenThreadToken` — open the impersonation token of the thread.
    OpenThreadToken,
    /// `RevertToSelf` — stop impersonating.
    RevertToSelf,
    /// `GetUserNameA` — the ANSI user-name query.
    GetUserNameA,
    /// `LogonUserW` — a logon session for the guest user.
    LogonUserW,
    // ── advapi32: service control manager ──────────────────────────────
    /// `CloseServiceHandle` — close an SCM manager/service handle.
    CloseServiceHandle,
    /// `ControlService` — the documented SERVICE_CONTROL_* state flow.
    ControlService,
    /// `CreateServiceW` — create a service in the guest registry DB.
    CreateServiceW,
    /// `DeleteService` — mark a service for deletion.
    DeleteService,
    /// `OpenSCManagerW` — open the service database.
    OpenSCManagerW,
    /// `OpenServiceW` — open a service handle.
    OpenServiceW,
    /// `QueryServiceStatus` — the documented SERVICE_STATUS structure.
    QueryServiceStatus,
    /// `StartServiceW` — START_PENDING → RUNNING status flow.
    StartServiceW,
    // ── advapi32: CryptoAPI (CSP) ──────────────────────────────────────
    /// `CryptAcquireContextW` — a provider context with a container name.
    CryptAcquireContextW,
    /// `CryptCreateHash` — a hash object (MD5/SHA-1/SHA-2).
    CryptCreateHash,
    /// `CryptDecrypt` — RC4/RC2/3DES/DES/AES decryption.
    CryptDecrypt,
    /// `CryptDeriveKey` — derive a key from a hash.
    CryptDeriveKey,
    /// `CryptDestroyHash` — release a hash object.
    CryptDestroyHash,
    /// `CryptDestroyKey` — release a key object.
    CryptDestroyKey,
    /// `CryptEncrypt` — RC4/RC2/3DES/DES/AES encryption with padding.
    CryptEncrypt,
    /// `CryptGenRandom` — the guest RNG (shared with BCryptGenRandom).
    CryptGenRandom,
    /// `CryptGetHashParam` — HP_ALGID/HP_HASHSIZE/HP_HASHVAL.
    CryptGetHashParam,
    /// `CryptHashData` — feed bytes into a hash object.
    CryptHashData,
    /// `CryptReleaseContext` — release a provider context.
    CryptReleaseContext,
    // ── advapi32: registry leftovers ───────────────────────────────────
    /// `RegEnumValueW` — enumerate a key's values.
    RegEnumValueW,
    /// `RegFlushKey` — the write-through registry flush.
    RegFlushKey,
    /// `RegOpenCurrentUser` — a handle to HKEY_CURRENT_USER.
    RegOpenCurrentUser,
    /// `RegQueryInfoKeyW` — key statistics from the guest registry.
    RegQueryInfoKeyW,
    // ── advapi32: ETW event source ─────────────────────────────────────
    /// `EventRegister` — register an event provider.
    EventRegister,
    /// `EventUnregister` — unregister an event provider.
    EventUnregister,
    /// `EventWrite` — publish an event record.
    EventWrite,
    // ── shell32: icon / path / notify helpers ──────────────────────────
    /// `ExtractIconW` — extract a module's icon resource as a HICON.
    ExtractIconW,
    /// `ExtractIconExW` — extract up to nIcons icon handles.
    ExtractIconExW,
    /// `PathIsNetworkPathW` — the UNC/device-path network test.
    PathIsNetworkPathW,
    /// `PathMakeUniqueName` — a non-conflicting file name.
    PathMakeUniqueName,
    /// `PathRelativePathToW` — the documented relative-path algorithm.
    PathRelativePathToW,
    /// `SHChangeNotify` — the documented no-op change notification.
    SHChangeNotify,
    /// `SHCreateDirectoryExW` — recursive mkdir via the filesystem layer.
    SHCreateDirectoryExW,
    /// `SHCreateShellItem` — a shell item from a PIDL.
    SHCreateShellItem,
    /// `SHFileOperationW` — copy/move/delete/rename file operations.
    SHFileOperationW,
    /// `SHGetMalloc` — the standard IMalloc allocator.
    SHGetMalloc,
    /// `SHUpdateImageW` — the documented no-op image-list update.
    SHUpdateImageW,
    /// `ShellExecuteW` — open a file/URL with the documented verb.
    ShellExecuteW,
    // IMalloc vtable methods (SHGetMalloc).
    SHMallocQueryInterface,
    SHMallocAddRef,
    SHMallocRelease,
    SHMallocAlloc,
    SHMallocRealloc,
    SHMallocFree,
    SHMallocGetSize,
    SHMallocDidAlloc,
    SHMallocHeapMinimize,
    // ── D3D9 Basic Rendering (Phase 1.5) ──────────────────────────────────────
    /// Direct3DCreate9 — top-level entry point for D3D9.
    Direct3DCreate9,
    /// Direct3DCreate9Ex — extended entry point.
    Direct3DCreate9Ex,
    // IDirect3D9 factory vtable methods
    D3d9FactoryCreateDevice,
    D3d9FactoryGetAdapterCount,
    D3d9FactoryGetAdapterIdentifier,
    D3d9FactoryGetAdapterModeCount,
    D3d9FactoryGetAdapterDisplayMode,
    D3d9FactoryGetDeviceCaps,
    // IDirect3DDevice9 vtable methods
    D3d9DeviceSetRenderState,
    D3d9DeviceGetRenderState,
    D3d9DeviceSetFVF,
    D3d9DeviceSetStreamSource,
    D3d9DeviceSetIndices,
    D3d9DeviceDrawPrimitive,
    D3d9DeviceDrawIndexedPrimitive,
    D3d9DeviceDrawPrimitiveUP,
    D3d9DeviceDrawIndexedPrimitiveUP,
    D3d9DeviceSetTransform,
    D3d9DeviceSetMaterial,
    D3d9DeviceSetLight,
    D3d9DeviceLightEnable,
    D3d9DeviceSetTexture,
    D3d9DeviceSetTextureStageState,
    D3d9DeviceSetViewport,
    D3d9DeviceSetScissorRect,
    D3d9DeviceSetClipPlane,
    D3d9DeviceSetPixelShader,
    D3d9DeviceSetVertexShader,
    D3d9DeviceSetPixelShaderConstantF,
    D3d9DeviceSetVertexShaderConstantF,
    D3d9DeviceSetSamplerState,
    D3d9DeviceBeginScene,
    D3d9DeviceEndScene,
    D3d9DevicePresent,
    D3d9DeviceReset,
    D3d9DeviceCreateVertexBuffer,
    D3d9DeviceCreateIndexBuffer,
    D3d9DeviceCreateTexture,
    D3d9DeviceCreateQuery,
    D3d9DeviceGetBackBuffer,
    D3d9DeviceGetRenderTarget,
    D3d9DeviceSetRenderTarget,
    D3d9DeviceGetDepthStencilSurface,
    D3d9DeviceSetDepthStencilSurface,
    D3d9DeviceClear,
    D3d9DeviceGetDeviceCaps,
    D3d9DeviceGetSwapChain,
    D3d9DeviceTestCooperativeLevel,
    D3d9DeviceGetViewport,
    D3d9DeviceGetTransform,
    D3d9DeviceGetTexture,
    D3d9DeviceGetStreamSource,
    D3d9DeviceGetIndices,
    // IDirect3DVertexBuffer9 vtable methods
    D3d9VertexBufferLock,
    D3d9VertexBufferUnlock,
    // IDirect3DIndexBuffer9 vtable methods
    D3d9IndexBufferLock,
    D3d9IndexBufferUnlock,
    // IDirect3DTexture9 vtable methods
    D3d9TextureLockRect,
    D3d9TextureUnlockRect,
    // IDirect3DSwapChain9 vtable methods
    D3d9SwapChainPresent,
    D3d9SwapChainGetBackBuffer,
    // -- DWM (Desktop Window Manager) --
    /// `dwmapi.dll!DwmIsCompositionEnabled` — queries whether DWM composition is enabled.
    DwmIsCompositionEnabled,
    /// `dwmapi.dll!DwmEnableComposition` — enables or disables DWM composition.
    DwmEnableComposition,
    /// `dwmapi.dll!DwmEnableBlurBehindWindow` — enables blur behind a window.
    DwmEnableBlurBehindWindow,
    /// `dwmapi.dll!DwmExtendFrameIntoClientArea` — extends window frame into client area.
    DwmExtendFrameIntoClientArea,
    /// `dwmapi.dll!DwmGetColorizationColor` — gets colorization color for DWM.
    DwmGetColorizationColor,
    /// `dwmapi.dll!DwmGetWindowAttribute` — retrieves DWM window attributes.
    DwmGetWindowAttribute,
    /// `dwmapi.dll!DwmSetWindowAttribute` — sets DWM window attributes.
    DwmSetWindowAttribute,
    /// `dwmapi.dll!DwmFlush` — flushes pending DWM rendering commands.
    DwmFlush,
    /// `dwmapi.dll!DwmRegisterThumbnail` — registers a desktop thumbnail.
    DwmRegisterThumbnail,
    /// `dwmapi.dll!DwmUpdateThumbnailProperties` — updates thumbnail properties.
    DwmUpdateThumbnailProperties,
    /// `dwmapi.dll!DwmUnregisterThumbnail` — unregisters a desktop thumbnail.
    DwmUnregisterThumbnail,
    /// `dwmapi.dll!DwmSetIconicThumbnail` — sets a static iconic thumbnail.
    DwmSetIconicThumbnail,
    /// `dwmapi.dll!DwmSetIconicLivePreviewBitmap` — sets a live preview bitmap.
    DwmSetIconicLivePreviewBitmap,
    // --- I3: Scrollbars ---
    /// `SetScrollInfo` — sets the parameters of a scroll bar.
    SetScrollInfo,
    /// `GetScrollInfo` — gets the parameters of a scroll bar.
    GetScrollInfo,
    /// `SetScrollPos` — sets the position of a scroll box.
    SetScrollPos,
    /// `GetScrollPos` — retrieves the position of the scroll box.
    GetScrollPos,
    /// `SetScrollRange` — sets the minimum and maximum scroll positions.
    SetScrollRange,
    /// `GetScrollRange` — retrieves the minimum and maximum scroll positions.
    GetScrollRange,
    /// `ShowScrollBar` — shows or hides a scroll bar.
    ShowScrollBar,
    /// `EnableScrollBar` — enables or disables one or both scroll bar arrows.
    EnableScrollBar,
    /// `ScrollWindow` — scrolls the contents of a window's client area.
    ScrollWindow,
    /// `ScrollDC` — scrolls a rectangle of pixels horizontally and vertically.
    ScrollDC,
    /// `ScrollWindowEx` — scrolls the content of a window's client area with extended options.
    ScrollWindowEx,
    /// `wintrust.dll!WinVerifyTrust` — Authenticode trust verification.
    WinVerifyTrust,
    // -- Phase O4: PPL (Protected Process Light) detection -------------------
    /// `IsProtectedProcess` — checks if a process handle refers to a protected process.
    IsProtectedProcess,
    /// `IsProtectedProcessLight` — checks if a process handle refers to a PPL process.
    IsProtectedProcessLight,
    /// `RtlIsProtectedProcess` — ntdll!RtlIsProtectedProcess
    RtlIsProtectedProcess,
    /// `RtlIsProtectedProcessLight` — ntdll!RtlIsProtectedProcessLight
    RtlIsProtectedProcessLight,
    // -- Phase O5: Credential guard simulation -------------------------------
    /// `CredIsProtected` — determines whether a credential is protected by Credential Guard.
    CredIsProtected,
    /// `CredProtectW` — protects a credential using Credential Guard.
    CredProtectW,
    /// `CredUnprotectW` — unprotects a credential that was protected by Credential Guard.
    CredUnprotectW,
    // -- Phase O3: Code integrity enforcement --------------------------------
    /// `NtQueryInformationProcess` — ntdll!NtQueryInformationProcess
    NtQueryInformationProcess,
    // -- Stage-4 NTDLL foundation: the native Windows API layer --------------
    // The Nt*/Rtl* dispatch arms build on the canonical layers (the single
    // VirtualMemory, the live object/handle namespace, the guest scheduler);
    // the implementations live in crate::ntdll + runtime::dispatch::ntdll.
    /// `NtAllocateVirtualMemory` — ntdll!NtAllocateVirtualMemory
    NtAllocateVirtualMemory,
    /// `NtFreeVirtualMemory` — ntdll!NtFreeVirtualMemory
    NtFreeVirtualMemory,
    /// `NtProtectVirtualMemory` — ntdll!NtProtectVirtualMemory
    NtProtectVirtualMemory,
    /// `NtQueryVirtualMemory` — ntdll!NtQueryVirtualMemory
    NtQueryVirtualMemory,
    /// `NtReadVirtualMemory` — ntdll!NtReadVirtualMemory
    NtReadVirtualMemory,
    /// `NtWriteVirtualMemory` — ntdll!NtWriteVirtualMemory
    NtWriteVirtualMemory,
    /// `NtClose` — ntdll!NtClose
    NtClose,
    /// `NtDuplicateObject` — ntdll!NtDuplicateObject
    NtDuplicateObject,
    /// `NtQueryObject` — ntdll!NtQueryObject
    NtQueryObject,
    /// `NtOpenDirectoryObject` — ntdll!NtOpenDirectoryObject
    NtOpenDirectoryObject,
    /// `NtQueryDirectoryObject` — ntdll!NtQueryDirectoryObject
    NtQueryDirectoryObject,
    /// `NtQueryVolumeInformationFile` — ntdll!NtQueryVolumeInformationFile
    NtQueryVolumeInformationFile,
    /// `NtAttestationChallenge` — Casa1 extension: issue a nonce challenge
    NtAttestationChallenge,
    /// `NtAttestationQuote` — Casa1 extension: sign a build measurement
    NtAttestationQuote,
    /// `NtAttestationVerify` — Casa1 extension: verify a quote
    NtAttestationVerify,
    /// `NtAttestationEnrollProvider` — Casa1 extension: enroll a provider key
    NtAttestationEnrollProvider,
    /// `NtAttestationRevokeProvider` — Casa1 extension: revoke a provider
    NtAttestationRevokeProvider,
    /// `NtCreateEvent` — ntdll!NtCreateEvent
    NtCreateEvent,
    /// `NtSetEvent` — ntdll!NtSetEvent
    NtSetEvent,
    /// `NtClearEvent` — ntdll!NtClearEvent
    NtClearEvent,
    /// `NtWaitForSingleObject` — ntdll!NtWaitForSingleObject
    NtWaitForSingleObject,
    /// `NtWaitForMultipleObjects` — ntdll!NtWaitForMultipleObjects
    NtWaitForMultipleObjects,
    /// `NtDelayExecution` — ntdll!NtDelayExecution
    NtDelayExecution,
    /// `NtTestAlert` — ntdll!NtTestAlert (deliver this thread's queued APCs)
    NtTestAlert,
    /// `NtCreateSection` — ntdll!NtCreateSection
    NtCreateSection,
    /// `NtMapViewOfSection` — ntdll!NtMapViewOfSection
    NtMapViewOfSection,
    /// `NtUnmapViewOfSection` — ntdll!NtUnmapViewOfSection
    NtUnmapViewOfSection,
    /// `NtQuerySection` — ntdll!NtQuerySection
    NtQuerySection,
    /// `NtCreateFile` — ntdll!NtCreateFile
    NtCreateFile,
    /// `NtLoadDriver` — ntdll!NtLoadDriver
    NtLoadDriver,
    /// `NtUnloadDriver` — ntdll!NtUnloadDriver
    NtUnloadDriver,
    /// `NtDeviceIoControlFile` — ntdll!NtDeviceIoControlFile
    NtDeviceIoControlFile,
    /// `NtReadFile` — ntdll!NtReadFile
    NtReadFile,
    /// `NtWriteFile` — ntdll!NtWriteFile
    NtWriteFile,
    /// `NtCreateKey` — ntdll!NtCreateKey
    NtCreateKey,
    /// `NtOpenKey` — ntdll!NtOpenKey
    NtOpenKey,
    /// `NtQueryValueKey` — ntdll!NtQueryValueKey
    NtQueryValueKey,
    /// `NtSetValueKey` — ntdll!NtSetValueKey
    NtSetValueKey,
    /// `NtDeleteKey` — ntdll!NtDeleteKey
    NtDeleteKey,
    /// `NtDeleteValueKey` — ntdll!NtDeleteValueKey
    NtDeleteValueKey,
    /// `NtEnumerateKey` — ntdll!NtEnumerateKey
    NtEnumerateKey,
    /// `NtEnumerateValueKey` — ntdll!NtEnumerateValueKey
    NtEnumerateValueKey,
    /// `NtQueryKey` — ntdll!NtQueryKey
    NtQueryKey,
    /// `NtQueryInformationThread` — ntdll!NtQueryInformationThread
    NtQueryInformationThread,
    /// `NtGetContextThread` — ntdll!NtGetContextThread
    NtGetContextThread,
    /// `NtSetContextThread` — ntdll!NtSetContextThread
    NtSetContextThread,
    /// `NtSuspendThread` — ntdll!NtSuspendThread
    NtSuspendThread,
    /// `NtResumeThread` — ntdll!NtResumeThread
    NtResumeThread,
    /// `NtTerminateProcess` — ntdll!NtTerminateProcess
    NtTerminateProcess,
    /// `NtTerminateThread` — ntdll!NtTerminateThread
    NtTerminateThread,
    /// `NtCreateThreadEx` — ntdll!NtCreateThreadEx
    NtCreateThreadEx,
    /// `NtSetInformationThread` — ntdll!NtSetInformationThread
    NtSetInformationThread,
    /// `NtQuerySystemInformation` — ntdll!NtQuerySystemInformation
    NtQuerySystemInformation,
    /// `NtQueryPerformanceCounter` — ntdll!NtQueryPerformanceCounter
    NtQueryPerformanceCounter,
    /// `NtQueryTimerResolution` — ntdll!NtQueryTimerResolution
    NtQueryTimerResolution,
    /// `NtSetTimerResolution` — ntdll!NtSetTimerResolution
    NtSetTimerResolution,
    /// `NtQuerySystemTime` — ntdll!NtQuerySystemTime
    NtQuerySystemTime,
    /// `RtlInitUnicodeString` — ntdll!RtlInitUnicodeString
    RtlInitUnicodeString,
    /// `RtlInitAnsiString` — ntdll!RtlInitAnsiString
    RtlInitAnsiString,
    /// `RtlFreeUnicodeString` — ntdll!RtlFreeUnicodeString
    RtlFreeUnicodeString,
    /// `RtlFreeAnsiString` — ntdll!RtlFreeAnsiString
    RtlFreeAnsiString,
    /// `RtlCompareUnicodeString` — ntdll!RtlCompareUnicodeString
    RtlCompareUnicodeString,
    /// `RtlEqualUnicodeString` — ntdll!RtlEqualUnicodeString
    RtlEqualUnicodeString,
    /// `RtlGetVersion` — ntdll!RtlGetVersion
    RtlGetVersion,
    /// `RtlCaptureContext` — ntdll!RtlCaptureContext
    RtlCaptureContext,
    /// `RtlLookupFunctionEntry` — ntdll!RtlLookupFunctionEntry
    RtlLookupFunctionEntry,
    /// `RtlRaiseException` — ntdll!RtlRaiseException
    RtlRaiseException,
    /// `RtlAllocateHeap` — ntdll!RtlAllocateHeap
    RtlAllocateHeap,
    /// `RtlFreeHeap` — ntdll!RtlFreeHeap
    RtlFreeHeap,
    /// `RtlSizeHeap` — ntdll!RtlSizeHeap
    RtlSizeHeap,
    // -- Stage-4 Ldr loader chain: the native loader surface ----------------
    // The Ldr layer is the NTDLL-native surface ABOVE the loader machinery
    // (resolve_load_library_handle / lookup_module_handle /
    // resolve_proc_address / load_real_dll + the pending-DllMain queue):
    // ONE loader implementation, native NTSTATUS protocol on top.
    /// `LdrLoadDll` — ntdll!LdrLoadDll
    LdrLoadDll,
    /// `LdrUnloadDll` — ntdll!LdrUnloadDll
    LdrUnloadDll,
    /// `LdrGetDllHandle` — ntdll!LdrGetDllHandle
    LdrGetDllHandle,
    /// `LdrGetProcedureAddress` — ntdll!LdrGetProcedureAddress
    LdrGetProcedureAddress,
    /// `LdrLockLoaderLock` — ntdll!LdrLockLoaderLock
    LdrLockLoaderLock,
    /// `LdrUnlockLoaderLock` — ntdll!LdrUnlockLoaderLock
    LdrUnlockLoaderLock,
    /// `LdrAddRefDll` — ntdll!LdrAddRefDll
    LdrAddRefDll,
    /// `LdrRemoveRefDll` — ntdll!LdrRemoveRefDll
    LdrRemoveRefDll,
    // -- Phase M2: Delay-load import hooking ----------------------------------
    /// `DelayLoadResolve` — resolves a delay-loaded import on first call.
    /// Stores the DLL name, symbol, and IAT slot RVA so that on first invocation
    /// the import is resolved (LoadLibrary + GetProcAddress), the IAT is patched,
    /// and the call is forwarded to the resolved thunk.
    DelayLoadResolve {
        resolved_module: String,
        symbol: ImportSymbol,
        iat_rva: u32,
        selected_base: u64,
    },
    // -- Phase M6: Hot-patching support -------------------------------------------
    /// `WriteProcessMemory` — writes data to memory in a specified process.
    /// In our emulator context, this is handled by reading the buffer from guest
    /// memory and writing it to the target address. If the target address points
    /// to a hot-patchable function entry, the write is redirected to patch the
    /// function's 5-byte JMP prefix instead.
    WriteProcessMemory,
    // ── Phase L: COM/Shell Completion ───────────────────────────────────────────
    /// L1 — IShellFolder
    SHGetDesktopFolder,
    SHBrowseForFolderW,
    ILCreateFromPathW,
    ILFree,
    SHParseDisplayName,
    SHCreateItemFromParsingName,
    SHCreateItemFromIDList,
    SHGetDataFromIDListW,
    SHBindToParent,
    SHGetSpecialFolderPathW,
    SHSimpleIDListFromPath,
    /// L3 — Drag-and-drop
    RegisterDragDrop,
    DoDragDrop,
    DragAcceptFiles,
    DragQueryFileW,
    DragFinish,
    /// L8 — URL moniker binding
    CreateURLMoniker,
    CheckRemoteDebuggerPresent,
    GetSystemFirmwareTable,
    GetVolumeInformationW,
    CreateAsyncBindCtx,
    RegisterBindStatusCallback,
    // ── Phase L: COM vtable method thunks ──────────────────────────────────
    /// IShellFolder::ParseDisplayName — converts a display name to a PIDL.
    ShellFolderParseDisplayName,
    /// IShellFolder::EnumObjects — enumerates objects in a folder.
    ShellFolderEnumObjects,
    /// IShellFolder::BindToObject — binds to a subfolder by PIDL.
    ShellFolderBindToObject,
    /// IShellFolder::GetDisplayNameOf — gets the display name of a PIDL.
    ShellFolderGetDisplayNameOf,
    /// IShellFolder::GetAttributesOf — gets attributes of PIDL items.
    ShellFolderGetAttributesOf,
    /// IShellFolder::GetUIObjectOf — gets a UI object (e.g. IContextMenu) for PIDLs.
    ShellFolderGetUIObjectOf,
    /// IContextMenu::QueryContextMenu — builds a context menu.
    ContextMenuQueryContextMenu,
    /// IContextMenu::InvokeCommand — executes a menu command.
    ContextMenuInvokeCommand,
    /// IContextMenu::GetCommandString — gets command verb/text.
    ContextMenuGetCommandString,
    /// IPropertyStore::GetCount — gets the number of properties.
    PropertyStoreGetCount,
    /// IPropertyStore::GetAt — gets a property key by index.
    PropertyStoreGetAt,
    /// IPropertyStore::GetValue — gets a property value.
    PropertyStoreGetValue,
    /// IPropertyStore::SetValue — sets a property value.
    PropertyStoreSetValue,
    /// IPropertyStore::Commit — persists property changes.
    PropertyStoreCommit,
    /// IXMLDOMDocument::loadXML — loads XML from a string.
    XmlDomLoadXml,
    /// IXMLDOMDocument::get_documentElement — gets the root element node.
    XmlDomGetDocumentElement,
    /// IXMLDOMDocument::selectNodes — runs an XPath query.
    XmlDomSelectNodes,
    /// IXMLDOMDocument::createElement — creates a new element node.
    XmlDomCreateElement,
    /// IXMLDOMNode::appendChild — appends a child node.
    XmlDomAppendChild,
    /// IXMLDOMNode::get_text / nodeValue — gets text content.
    XmlDomGetText,
    /// IXMLDOMNodeList::get_length — gets node list count.
    XmlDomNodeListGetLength,
    /// IXMLDOMNodeList::get_item — gets a node by index.
    XmlDomNodeListGetItem,
    /// IMoniker::BindToStorage — binds to storage of the URL moniker.
    MonikerBindToStorage,
    /// IMoniker::GetDisplayName — gets the display name string.
    MonikerGetDisplayName,
    /// IXMLDOMDocument::get_xml — serialises the DOM tree to XML string.
    XmlDomGetXml,
    /// IXMLDOMDocument::getElementsByTagName — finds elements by tag name.
    XmlDomGetElementsByTagName,
    /// IXMLDOMDocument::createTextNode — creates a text node.
    XmlDomCreateTextNode,
    /// IXMLDOMDocument::transformNode — applies an XSLT stylesheet.
    XmlDomTransformNode,
    /// IMoniker::BindToObject — binds to the moniker's object.
    MonikerBindToObject,
    /// IMoniker::Reduce — reduces the moniker.
    MonikerReduce,
    /// IMoniker::ComposeWith — composes two monikers.
    MonikerComposeWith,
    /// IMoniker::Enum — enumerates the moniker's components.
    MonikerEnum,
    /// IMoniker::IsSystemMoniker — checks if this is a system moniker.
    MonikerIsSystemMoniker,
    /// IMoniker::Hash — gets the hash of the moniker.
    MonikerHash,
    // ── Phase L1: IEnumIDList methods ──────────────────────────────────────
    /// IEnumIDList::Next — retrieves the next celt PIDLs in the enumeration.
    EnumIDListNext,
    /// IEnumIDList::Skip — skips the next celt PIDLs.
    EnumIDListSkip,
    /// IEnumIDList::Reset — resets the enumeration to the beginning.
    EnumIDListReset,
    /// IEnumIDList::Clone — creates a copy of the enumerator.
    EnumIDListClone,
    // ── CRT locale support ──────────────────────────────────────────────────
    /// setlocale — gets or sets the C locale (needed by Steam's CRT init).
    Setlocale,
    // ── Patch 6b: CRT / UCRT / MSVCRT host-thunk surface ─────────────────────
    /// `_errno` — returns a guest pointer to the per-thread errno int.
    CrtErrno,
    /// `_doserrno` — returns a guest pointer to the per-thread doserrno int.
    CrtDoserrno,
    /// `_get_errno` — copies the current errno to an out-param; returns 0.
    GetErrno,
    /// `_set_errno` — sets errno from an argument; returns the previous value.
    SetErrno,
    /// `__stdio_common_vsnprintf_s` — secure bounded narrow sprintf (6 args).
    StdioCommonVsnprintfS,
    /// `__stdio_common_vsprintf_s` — secure narrow sprintf (6 args).
    StdioCommonVsprintfS,
    /// `__stdio_common_vsnprintf` — legacy bounded narrow sprintf (6 args).
    StdioCommonVsnprintf,
    Memcpy,
    Memmove,
    Memset,
    Memcmp,
    Memchr,
    Strcpy,
    Strncpy,
    Strcat,
    Strncat,
    Strcmp,
    Strchr,
    Strstr,
    Stricmp,
    Strnicmp,
    Strerror,
    /// `_strerror` — "prefix: message" form of strerror.
    StrerrorPrefix,
    Wcslen,
    Wcscpy,
    Wcscat,
    Wcscmp,
    Wcsncpy,
    Wcsrchr,
    Wcschr,
    Wcsstr,
    Wcsnlen,
    Wcsicmp,
    Wcsnicmp,
    StrcpyS,
    StrncpyS,
    StrcatS,
    StrncatS,
    MemcpyS,
    MemmoveS,
    WcscpyS,
    WcsncpyS,
    Isalpha,
    Isdigit,
    Isalnum,
    Isxdigit,
    Isspace,
    Isupper,
    Islower,
    Ispunct,
    Isprint,
    Isgraph,
    Iscntrl,
    Tolower,
    Toupper,
    Atoi,
    Atol,
    Atof,
    Strtol,
    Strtoul,
    Strtoi64,
    Strtoi64S,
    Strtoui64,
    Strtoui64S,
    Abs,
    Labs,
    Div,
    Ldiv,
    Qsort,
    Bsearch,
    Getcwd,
    Wgetcwd,
    Chdir,
    Wchdir,
    Access,
    Waccess,
    Chmod,
    Wchmod,
    Stat,
    Wstat,
    Stat64,
    Wstat64,
    Fstat,
    Fstat64,
    Getenv,
    Wgetenv,
    DupenvS,
    WdupenvS,
    Putenv,
    Wputenv,
    Splitpath,
    Wsplitpath,
    SplitpathS,
    WsplitpathS,
    Makepath,
    Wmakepath,
    MakepathS,
    WmakepathS,
    Rand,
    Srand,
    Clock,
    Time,
    Time64,
    Beginthreadex,
    Endthreadex,
    Beginthread,
    Endthread,
    Fopen,
    Wfopen,
    FopenS,
    WfopenS,
    Fsopen,
    Freopen,
    Fdopen,
    Fclose,
    Fflush,
    Fread,
    Fgets,
    Fputs,
    Fgetc,
    Fputc,
    Fseek,
    Ftell,
    FreadS,
    FwriteS,
    Fcloseall,
    Flushall,
    Lock,
    Unlock,
    Fileno,
    Filelength,
    Filelengthi64,
    Chsize,
    Isatty,
    Commit,
    // ── Patch 6c: msvcrt math / stdio surface ────────────────────────────────
    /// `atan2(y, x)` — arc tangent of y/x (two double args, double result).
    CrtAtan2,
    /// `ceil(x)` — smallest integral value >= x.
    CrtCeil,
    /// `cos(x)` — cosine.
    CrtCos,
    /// `exp(x)` — base-e exponential.
    CrtExp,
    /// `fabs(x)` — absolute value of a double.
    CrtFabs,
    /// `floor(x)` — largest integral value <= x.
    CrtFloor,
    /// `log(x)` — natural logarithm.
    CrtLog,
    /// `pow(x, y)` — x raised to the power y (two double args, double result).
    CrtPow,
    /// `sin(x)` — sine.
    CrtSin,
    /// `sqrt(x)` — square root.
    CrtSqrt,
    /// `tan(x)` — tangent.
    CrtTan,
    /// `printf(format, ...)` — narrow-format printf to the guest stdout.
    CrtPrintf,
    /// `sprintf(buffer, format, ...)` — narrow-format formatted string write.
    CrtSprintf,
    /// `vsprintf(buffer, format, va_list)` — narrow-format with a caller va_list.
    CrtVsprintf,
    /// `sscanf(buffer, format, ...)` — narrow-format scan into out-params.
    CrtSscanf,
    /// `strrchr(str, ch)` — pointer to the last occurrence of a char.
    Strrchr,
    /// `wcsncmp(a, b, count)` — compare up to count wide chars.
    Wcsncmp,
    // ── Patch 6c: msvcp140.dll C++ runtime surface ───────────────────────────
    /// `_Cnd_init(cnd)` — initialize a C11 condition variable (allocates the
    /// internal block and writes the opaque handle through `cnd`).
    MsvcpCndInit,
    /// `_Cnd_destroy(cnd)` — release a C11 condition variable.
    MsvcpCndDestroy,
    /// `_Cnd_signal(cnd)` — wake one waiter.
    MsvcpCndSignal,
    /// `_Cnd_broadcast(cnd)` — wake all waiters.
    MsvcpCndBroadcast,
    /// `_Cnd_wait(cnd, mtx)` — atomically release `mtx` and wait; re-acquire
    /// before returning.
    MsvcpCndWait,
    /// `_Mtx_init(mtx, type)` — allocate and initialize a mutex (plain /
    /// recursive / timed per `_Mtx_plain` / `_Mtx_recursive` / `_Mtx_timed`).
    MsvcpMtxInit,
    /// `_Mtx_destroy(mtx)` — release a mutex.
    MsvcpMtxDestroy,
    /// `_Mtx_lock(mtx)` — block until the mutex is acquired.
    MsvcpMtxLock,
    /// `_Mtx_unlock(mtx)` — release the mutex.
    MsvcpMtxUnlock,
    /// `_Mtx_current(mtx)` — the owning thread id, or 0 when not owned.
    MsvcpMtxCurrent,
    /// `_Mtx_reset(mtx)` — reset a recursive mutex (owner died while held).
    MsvcpMtxReset,
    /// `_Xbad_alloc` — throw `std::bad_alloc` (MSVC C++ exception 0xE06D7363).
    MsvcpXbadAlloc,
    /// `_Xinvalid_argument(message)` — throw `std::invalid_argument`.
    MsvcpXinvalidArgument,
    /// `_Xlength_error(message)` — throw `std::length_error`.
    MsvcpXlengthError,
    /// `_Xout_of_range(message)` — throw `std::out_of_range`.
    MsvcpXoutOfRange,
    /// `_Xoverflow_error(message)` — throw `std::overflow_error`.
    MsvcpXoverflowError,
    /// `_Xruntime_error(message)` — throw `std::runtime_error`.
    MsvcpXruntimeError,
    /// `std::_Throw_C_error(errc)` — throw `std::system_error` for a C errc.
    MsvcpThrowCError,
    /// `std::_Throw_Cpp_error(errc)` — throw `std::system_error` for a C++ errc.
    MsvcpThrowCppError,
    /// `std::random_device::_Get()` — one `unsigned int` of entropy.
    MsvcpRandomDeviceGet,
    /// `std::random_device::_Init()` — initialize the entropy source.
    MsvcpRandomDeviceInit,
    // ── WinINet network status ──────────────────────────────────────────────
    /// InternetGetConnectedState — returns whether the system has network connectivity.
    InternetGetConnectedState,
    Unsupported {
        dll: String,
        symbol: String,
    },
    ClsidFromString,
    StringFromClsid,
    StringFromGuid2,
    ProgidFromClsid,
    ClsidFromProgid,
    CoTaskMemAlloc,
    CoTaskMemRealloc,
    CoFileTimeNow,
    CoDosDateTimeToFileTime,
    CoAddRefServerProcess,
    CoReleaseServerProcess,
    CoSuspendClassObjects,
    CoResumeClassObjects,
    CoGetCurrentProcess,
    CoGetApartmentType,
    CoInitialize,
    CoInitializeSecurity,
    CoImpersonateClient,
    CoRevertToSelf,
    CoAllowSetForegroundWindow,
    CoDisconnectObject,
    CoLockObjectExternal,
    CoRegisterMessageFilter,
    CoRegisterPsClsid,
    CoGetPsClsid,
    CoGetTreatAsClass,
    CoGetCallContext,
    CoSetProxyBlanket,
    CoCopyProxy,
    CoLoadLibrary,
    CoFreeLibrary,
    CoFreeUnusedLibraries,
    CoFreeAllLibraries,
    DllCanUnloadNow,
    DllRegisterServer,
    DllUnregisterServer,
    DllGetClassObject,
    AmGetErrorTextW,
    DshowClassFactoryCreateInstance,
    DshowClassFactoryLockServer,
    DshowFilterGraphRenderFile,
    DshowFilterGraphRender,
    ClrCreateInstance,
    CorBindToRuntime,
    CorBindToRuntimeEx,
    GetCorSystemDirectory,
    GetRequestedRuntimeInfo,
    LoadLibraryShim,
    // ── CLR meta host / ICLRRuntimeInfo / IEnumUnknown methods ────────────
    ClrMetaHostQueryInterface,
    ClrMetaHostAddRef,
    ClrMetaHostRelease,
    ClrMetaHostGetRuntime,
    ClrMetaHostGetVersionFromFile,
    ClrMetaHostEnumerateInstalledRuntimes,
    ClrMetaHostEnumerateLoadedRuntimes,
    ClrMetaHostRequestRuntimeLoadedNotification,
    ClrMetaHostQueryLegacyV2RuntimeBinding,
    ClrMetaHostExitProcess,
    ClrRuntimeInfoQueryInterface,
    ClrRuntimeInfoAddRef,
    ClrRuntimeInfoRelease,
    ClrRuntimeInfoGetVersionString,
    ClrRuntimeInfoGetRuntimeDirectory,
    ClrRuntimeInfoIsLoaded,
    ClrRuntimeInfoLoadErrorString,
    ClrRuntimeInfoLoadLibrary,
    ClrRuntimeInfoGetProcAddress,
    ClrRuntimeInfoGetInterface,
    // ── ICLRRuntimeHost methods ──────────────────────────────────────────
    ClrRuntimeHostQueryInterface,
    ClrRuntimeHostAddRef,
    ClrRuntimeHostRelease,
    ClrRuntimeHostStart,
    ClrRuntimeHostStop,
    ClrRuntimeHostSetHostControl,
    ClrRuntimeHostGetClrControl,
    ClrRuntimeHostUnloadAppDomain,
    ClrRuntimeHostExecuteInAppDomain,
    ClrRuntimeHostGetCurrentAppDomainId,
    ClrRuntimeHostExecuteApplication,
    ClrRuntimeHostExecuteInDefaultAppDomain,
    ClrEnumUnknownQueryInterface,
    ClrEnumUnknownAddRef,
    ClrEnumUnknownRelease,
    ClrEnumUnknownNext,
    ClrEnumUnknownSkip,
    ClrEnumUnknownReset,
    ClrEnumUnknownClone,
    ClrRuntimeLoadedCallbackThreadSet,
    ClrRuntimeLoadedCallbackThreadUnset,
    ClrHostExport {
        runtime_version: String,
        symbol: String,
    },
    DirectDrawCreate,
    DirectDrawCreateEx,
    DirectDrawEnumerateW,
    DirectDrawEnumerateExW,
    DirectDrawGetCaps,
    DirectDrawSetCooperativeLevel,
    DirectDrawSetDisplayMode,
    DirectDrawCreateSurface,
    DirectDrawEnumSurfaces,
    DirectDrawGetVerticalBlankStatus,
    DirectDrawSurfaceBlt,
    DirectDrawSurfaceFlip,
    DirectDrawSurfaceLock,
    DirectDrawSurfaceUnlock,
    DirectDrawSurfaceGetSurfaceDesc,
    D3dPerfBeginEvent,
    D3dPerfEndEvent,
    D3dPerfGetStatus,
    D3dPerfQueryRepeatFrame,
    D3dPerfSetMarker,
    D3dPerfSetOptions,
    DebugSetLevel,
    DebugSetMute,
    D3d10CreateDevice,
    D3d10CreateDeviceAndSwapChain,
    D3d10CoreCreateDevice,
    D3d10CoreCreateLayeredDevice,
    D3d10CoreGetSupportedVersions,
    D3d10CoreRegisterLayers,
    D3d10Level9CreateDevice,
    D3d10Level9GetSupportedVersions,
    D3d10CreateEffectFromMemory,
    D3d10CreateStateBlock,
    D3dCreateBlob,
    D3dBlobGetBufferPointer,
    D3dBlobGetBufferSize,
    D3dCompile,
    D3dCompile2,
    D3dCompileFromFile,
    D3dDisassemble,
    D3dGetBlobPart,
    D3dGetTraceInstructionOffsets,
    D3dLoadModule,
    D3dReflect,
    D3dSetBlobPart,
    D3dSetTraceInstructionOffsets,
    D3dStripShader,
    D3dCreateLinker,
    D3dx11CompileFromFile,
    D3dx11CompileFromFileW,
    D3dx11CreateAsyncShaderResourceViewProcessor,
    D3dx11CreateShaderResourceViewFromFile,
    D3dx11CreateShaderResourceViewFromFileW,
    D3dx11CreateTextureFromFileW,
    D3dx11CreateTextureFromMemory,
    D3dx11FilterTexture,
    D3dx11GetImageInfoFromFile,
    D3dx11GetImageInfoFromFileW,
    D3dx11LoadTextureFromTexture,
    D3dx11SaveTextureToFileW,
    D3dx11SaveTextureToMemory,
    IsAppThemed,
    IsThemeActive,
    OpenThemeData,
    CloseThemeData,
    SetWindowTheme,
    GetThemeColor,
    GetThemeSysColor,
    GetThemeSysFont,
    GetThemePartSize,
    GetThemeBackgroundContentRect,
    GetThemeTextExtent,
    GetThemeFont,
    DrawThemeBackground,
    DrawThemeText,
    EnableThemeDialogTexture,
    BufferedPaintInit,
    BufferedPaintUnInit,
    BeginBufferedPaint,
    EndBufferedPaint,
    BeginPanningFeedback,
    EndPanningFeedback,
    ImagehlpApiVersion,
    MapAndLoad,
    ImageLoad,
    UnMapAndLoad,
    ImageUnload,
    BindImage,
    BindImageEx,
    CheckSumMappedFile,
    ImageGetDigestStream,
    ImageEnumerateCertificates,
    ImageGetCertificateHeader,
    ImageGetCertificateData,
    ImageAddCertificate,
    ImageRemoveCertificate,
    HidDGetHidGuid,
    HidDGetAttributes,
    HidDGetProductString,
    HidDGetManufacturerString,
    HidDGetPreparsedData,
    HidDFreePreparsedData,
    HidPGetCaps,
    HidPGetButtonCaps,
    HidPGetValueCaps,
    HidPGetUsageValue,
    HidPGetUsages,
    HidPSetUsages,
    AcmDriverClose,
    AcmDriverEnum,
    AcmDriverMessage,
    AcmDriverOpen,
    AcmFormatDetails,
    AcmFormatDetailsW,
    AcmFormatEnum,
    AcmFormatEnumW,
    AcmFormatSuggest,
    AcmMetrics,
    AcmStreamClose,
    AcmStreamConvert,
    AcmStreamOpen,
    AcmStreamSize,
    MsiCloseAllHandles,
    MsiCloseHandle,
    MsiConfigureProductW,
    MsiCreateRecord,
    MsiDatabaseCommit,
    MsiDatabaseOpenViewW,
    MsiEnumProductsW,
    MsiGetProductInfoW,
    MsiGetPropertyW,
    MsiInstallProductW,
    MsiOpenDatabaseW,
    MsiOpenPackageW,
    MsiQueryProductInfoW,
    MsiRecordDataSize,
    MsiRecordGetInteger,
    MsiRecordGetStringW,
    MsiRecordReadStream,
    MsiRecordSetInteger,
    MsiRecordSetStringW,
    MsiReinstallProductW,
    MsiSetPropertyW,
    MsiViewClose,
    MsiViewExecute,
    MsiViewFetch,
    MsiViewGetColumnInfo,
    MsiViewModify,
    OleIidMoniker,
    OleIidStream,
    OleIidStorage,
    OleIidMalloc,
    OleIidPersist,
    OleIidDropTarget,
    OleIidDataObject,
    OleIidOleObject,
    OleIidInPlaceObject,
    OleIidObjectWithSite,
    OleIidServiceProvider,
    OleIidEnumVariant,
    OleIidConnectionPoint,
    OleDispGetParam,
    OleDispGetIdsOfNames,
    OleDispInvoke,
    OleCreateDispTypeInfo,
    OleCreateStdDispatch,
    OleGetRunningObjectTable,
    OleLoadTypeLib,
    OleLoadRegTypeLib,
    OleQueryPathOfRegTypeLib,
    OleRegisterTypeLib,
    OleUnRegisterTypeLib,
    NCryptCreatePersistedKey,
    NCryptDecrypt,
    NCryptDeleteKey,
    NCryptDeriveKey,
    NCryptEncrypt,
    NCryptExportKey,
    NCryptFinalizeKey,
    NCryptFreeBuffer,
    NCryptGetProperty,
    NCryptImportKey,
    NCryptIsAlgSupported,
    NCryptOpenKey,
    NCryptOpenStorageProvider,
    NCryptSecretAgreement,
    NCryptSetProperty,
    NCryptSignHash,
    NCryptVerifySignature,
    IRpcExceptionFilter,
    RpcBindingFree,
    RpcBindingFromStringBindingW,
    RpcStringBindingComposeW,
    RpcStringBindingFromStringBindingW,
    RpcStringFreeW,
    UuidCreate,
    UuidCreateSequential,
    UuidFromStringW,
    UuidToStringW,
    InitPropVariantFromGUIDAsString,
    InitPropVariantFromString,
    PSGetNameFromPropertyKey,
    PSGetPropertyDescriptionFromName,
    PSGetPropertyKeyFromName,
    PSPropertyKeyFromString,
    PSStringFromPropertyKey,
    PropVariantClear,
    PropVariantCopy,
    ImmGetCompositionStringW,
    ImmGetOpenStatus,
    ImmGetContext,
    ImmGetDefaultIMEWnd,
    ImmGetVirtualKey,
    ImmIsIME,
    ImmNotifyIME,
    ImmReleaseContext,
    ImmSetCompositionStringW,
    ImmSimulateHotKey,
    GetOpenFileNameW,
    GetSaveFileNameW,
    ChooseColorW,
    ChooseFontW,
    FindTextW,
    ReplaceTextW,
    PageSetupDlgW,
    PrintDlgW,
    PrintDlgExW,
    CommDlgExtendedError,
    GetProfilesDirectoryW,
    GetProfileType,
    CreateEnvironmentBlock,
    DestroyEnvironmentBlock,
    LoadUserProfileW,
    UnloadUserProfile,
    CreateAppContainerProfile,
    DeleteAppContainerProfile,
    GetAppContainerProfilePath,
    WNetAddConnection2W,
    WNetCancelConnection2W,
    WNetCloseEnum,
    WNetEnumResourceW,
    WNetGetConnectionW,
    WNetGetUserW,
    WNetOpenEnumW,
    TfCreateCategoryMgr,
    TfCreateDisplayAttributeMgr,
    TfCreateThreadMgr,
    TfGetThreadMgr,
    TfInitSystem,
    TfUninitSystem,
    BasicClassAddRef,
    LdapBindS,
    LdapCountEntries,
    LdapFirstEntry,
    LdapGetDn,
    LdapGetValues,
    LdapInit,
    LdapMemfree,
    LdapMsgfree,
    LdapNextEntry,
    LdapResult,
    LdapSearch,
    LdapSearchS,
    LdapUnbind,
    LdapValueFreeLen,
    HttpAddUrl,
    HttpCreateHttpHandle,
    HttpInitialize,
    HttpReceiveHttpRequest,
    HttpRemoveUrl,
    HttpSendHttpResponse,
    HttpSendResponseEntityBody,
    HttpTerminate,
    HttpWaitForDisconnect,
    PdhAddCounter,
    PdhCloseQuery,
    PdhCollectQueryData,
    PdhEnumCounters,
    PdhEnumObjects,
    PdhGetFormattedCounterValue,
    PdhOpenQuery,
    PdhRemoveCounter,
    EvtClose,
    EvtCreateBookmark,
    EvtNext,
    EvtOpenLog,
    EvtOpenSession,
    EvtQuery,
    EvtRender,
    EvtSubscribe,
    WlanCloseHandle,
    WlanConnect,
    WlanDisconnect,
    WlanEnumInterfaces,
    WlanGetAvailableNetworkList,
    WlanOpenHandle,
    WlanQueryInterface,
    WlanScan,
    BasicClassGetIDsOfNames,
    BasicClassInvoke,
    BasicClassQueryInterface,
    BasicClassRelease,
    BasicDispatchInvoke,
    DllCall,
    DllFunc,
    DllMain,
    DllProc,
    D3DKMTAcquireKeyedMutex,
    D3DKMTAcquireKeyedMutex2,
    D3DKMTCloseAdapter,
    D3DKMTCreateAllocation,
    D3DKMTCreateContext,
    D3DKMTCreateDevice,
    D3DKMTCreateSwapChain,
    D3DKMTCreateSynchronizationObject,
    D3DKMTDestroyAllocation,
    D3DKMTDestroyContext,
    D3DKMTDestroyDevice,
    D3DKMTDestroySwapchain,
    D3DKMTDestroySynchronizationObject,
    D3DKMTEnumAdapters,
    D3DKMTEnumOutputs,
    D3DKMTEscape,
    D3DKMTEvict,
    D3DKMTMapGpuVirtualAddress,
    D3DKMTPagingFence,
    D3DKMTQueryVideoMemoryInfo,
    D3DKMTSubmitCommand,
    D3DKMTUnmapGpuVirtualAddress,
    D3DKMTGetDisplayModeList,
    D3DKMTGetDisplayModeList2,
    D3DKMTGetGammaRamp,
    D3DKMTMakeResident,
    D3DKMTOpenAdapterFromDeviceName,
    D3DKMTOpenAdapterFromGdiDisplayName,
    D3DKMTOpenAdapterFromHdc,
    D3DKMTOpenAdapterFromLuid,
    D3DKMTOpenDevice,
    D3DKMTOpenKeyedMutex,
    D3DKMTOpenKeyedMutex2,
    D3DKMTOpenResource,
    D3DKMTOpenResource2,
    D3DKMTPnPStart,
    D3DKMTPnPStop,
    D3DKMTPowerComponent,
    D3DKMTPresent,
    D3DKMTQueryAdapterInfo,
    D3DKMTReleaseKeyedMutex,
    D3DKMTReleaseKeyedMutex2,
    D3DKMTQueryAllocationResidency,
    D3DKMTQueryStatistics,
    D3DKMTQuerySwapChainInfo,
    D3DKMTRender,
    D3DKMTSetAllocationPriority,
    D3DKMTSetCursor,
    D3DKMTSetCursorPosition,
    D3DKMTSetDisplayPrivateDriverFormat,
    D3DKMTSetGammaRamp,
    D3DKMTSignalSynchronizationObject,
    D3DKMTSignalSynchronizationObject2,
    D3DKMTWaitForSynchronizationObject,
    D3DKMTWaitForSynchronizationObject2,
    JetAttachDatabase,
    JetBeginTransaction,
    JetCloseDatabase,
    JetCloseTable,
    JetCommitTransaction,
    JetCreateDatabase,
    JetDetachDatabase,
    JetGetTableColumnInfo,
    JetInit,
    JetOpenDatabase,
    JetOpenTable,
    JetRollback,
    JetTerm,
    WSPAccept,
    WSPBind,
    WSPCleanup,
    WSPConnect,
    WSPListen,
    WSPRecv,
    WSPSend,
    WSPSocket,
    WSPStartup,
    AcceptEx,
    EnumProtocolsW,
    GetAcceptExSockaddrs,
    TransmitFile,
    WSAGetOverlappedResult,
    WSARecvEx,
    WSASocketW,
    HttpAddRequestHeadersW,
    HttpQueryInfoW,
    InternetAttemptConnect,
    InternetOpenUrlW,
    InternetQueryOptionW,
    InternetReadFileExW,
    InternetWriteFile,
    DirectInputCreateEx,
    DirectInputCreateW,
    DirectInputCreateDevice,
    WmcdspCreateAudioDecoder,
    WmcdspCreateAudioEncoder,
    WmcdspCreateConverter,
    WmcdspCreateDecoder,
    WmcdspCreateEncoder,
    WmcdspCreateProcessor,
    WmcdspCreateResampler,
    WmCreateEditor,
    WmCreateIndexer,
    WmCreateProfileManager,
    WmCreateReader,
    WmCreateSyncReader,
    WmCreateWriter,
    WmIsContentProtected,
    AudioSessionFromGuid,
    AudioSessionFromHwnd,
    AudioSessionFromString,
    AudioSessionize,
    DmoEnum,
    DmoGetName,
    DmoGetTypes,
    DmoGuidToStr,
    DmoStrToGuid,
    MoFree,
    MfCreateVideoMediaType,
    MfCreateVideoMixer,
    MfCreateVideoPresenter,
    MfCreateVideoRenderer,
    MfCreateVideoSampleAllocator,
    AmGetErrorText,
    CreateErrorInfo,
    CreateFilter,
    Dxva2CreateDirect3DDeviceManager9,
    Dxva2CreateVideoService,
    Dxva2GetVideoProcessorCaps,
    CpAcquireContext,
    CpDecrypt,
    CpEncrypt,
    CpGenKey,
    CpHashData,
    CpReleaseContext,
    CpVerifySignature,
    CryptProtectData,
    CryptProtectMemory,
    CryptUnprotectData,
    CryptUnprotectMemory,
    WtGetSignatureInfo,
    WtHelperGetProvPrivateDataFromChain,
    WtHelperGetProvSignerFromChain,
    WtHelperProvDataFromStateData,
    CryptDecodeObject,
    CryptEncodeObject,
    CryptExportPkcs8,
    FreeContextBuffer,
    QuerySecurityPackageInfoW,
    SspiInitialize,
    InitSecurityInterfaceW,
    SslGetDataToWrite,
    SslLoadCertificate,
    ImageListGetIcon,
    ImageListGetIconSize,
    ImageListSetIconSize,
    PropertySheetW,
    CmFreeDeviceIdList,
    CmGetDevNodeStatus,
    CmGetDeviceIdListW,
    CmGetDeviceIdListSizeW,
    CmLocateDevNodeW,
    PowerGetActiveScheme,
    PowerReadACValue,
    PowerReadDCValue,
    PowerSetActiveScheme,
    WimApplyImage,
    WimCloseHandle,
    WimCreateFile,
    WimLoadImage,
    WimUnmountImageHandle,
    RoActivateInstance,
    RoGetActivationFactory,
    RoInitialize,
    RoUninitialize,
    CreateXmlReader,
    CreateXmlReaderInputWithEncoding,
    CreateXmlWriter,
    CreateXmlWriterOutputWithEncoding,
    CoInternetIsFeatureEnabled,
    CoInternetSetFeatureEnabled,
    ObtainUserAgentString,
    UrlDownloadToCacheFileW,
    UrlDownloadToFileW,
    WinHttpCrackUrl,
    WinHttpCreateUrl,
    WinHttpDetectAutoProxyConfigUrl,
    WinHttpTimeFromSystemTime,
    WinHttpTimeToSystemTime,
    SpCreateObjectFromKey,
    SpCreateObjectFromToken,
    SpEnumTokens,
    SpGetCategoryFromId,
    SpGetDescription,
    RasDial,
    RasEnumConnections,
    RasGetConnectionStatus,
    RasGetErrorString,
    RasHangUp,
    RasSetEntryProperties,
    WmiClose,
    WmiConnect,
    WmiInitialize,
    WmiQuery,
    UiaGetPatternProvider,
    UiaGetRuntimeId,
    UiaGetUpdatedCache,
    UiaLookupId,
    UiaNavigate,
    UiaRaiseAutomationEvent,
    UiaRaiseAutomationPropertyChangedEvent,
    AccessibleObjectFromEvent,
    AccessibleObjectFromPoint,
    AccessibleObjectFromWindow,
    GetAccessibleObjectFromWindow,
    GetOleaccVersionInfo,
    WindowFromAccessibleObject,
    DhcpCApiCleanup,
    DhcpCApiInitialize,
    DhcpReleaseParams,
    DhcpRenewParams,
    DhcpRequestParams,
    DnsFlushResolverCache,
    DnsQueryConfig,
    DnsQueryW,
    DnsRecordListFree,
    DiInstallDevice,
    DiInstallDriverW,
    DiUninstallDevice,
    UpdateDriverForPlugAndPlayDevicesW,
    WtsEnumerateSessionsW,
    WtsFreeMemory,
    WtsQuerySessionInformationW,
    WtsQueryUserToken,
    CreateVssBackupComponents,
    VssFreeComponent,
    VssFreeSnapshotProperties,
    VssFreeWriterMetadata,
    CreateTextServices,
    ITextDocument,
    RichEdit10AnsiWndClass,
    ShutdownTextServices,
    Dp8spCreate,
    DirectPlay8Create,
    DirectSoundCaptureCreate8,
    DirectSoundCaptureEnumerateW,
    AtlModuleAddTermFunc,
    AtlModuleLoadTypeLib,
    AtlModuleRegisterServer,
    AtlModuleRegisterTypeLib,
    AtlModuleUnregisterServer,
    AtlModuleUnregisterTypeLib,
    AtlModuleUpdateRegistryFromResource,
    WicCreateAvifDecoder,
    WicCreateAvifEncoder,
    WicCreateHeifDecoder,
    WicCreateHeifEncoder,
    WicCreateWebpDecoder,
    WicCreateWebpEncoder,
    DllInstall,
    OverlayCreateHook,
    OverlayHookWindow,
    OverlayPresent,
    OverlayReset,
    OverlayUnhookWindow,
    CndInit,
    MtxDestroy,
    MtxInit,
    MtxLock,
    MtxUnlock,
    SteamBGetSteamId,
    SteamBIsSubscribedApp,
    SteamBLoggedOn,
    SteamNotifyOfLogin,
    SteamNotifyOfLogoff,
    CCSpecificHandler,
    CurrentException,
    CurrentExceptionContext,
    ProcessingThrow,
    Chkstk,
    CertSrvBackupEnd,
    CertSrvBackupPrepare,
    CertSrvRestoreEnd,
    CertSrvRestorePrepare,
    D3dx10CompileFromFile,
    D3dx10CreateTextureFromFileW,
    D3dx10GetImageInfoFromFile,
    D3dx10SaveTextureToMemory,
    GameuxShfolderpath,
    GameExplorerInitialize,
    GameExplorerSetUserAccess,
    GameExplorerVerifyAccess,
    ClrCreateManagedInstance,
    GetClrRuntimeHost,
    CreateHtmlPropertyPage,
    IeFrameFactoryConstructor,
    ShowHtmlDialogEx,
    IhtmlDocument2,
    DsBind,
    DsBindWithCred,
    DsMakeSpnW,
    DsUnbind,
    CredSspGetClientCredential,
    CredSspGetServerCredential,
    ShCreateExplorerTaskband,
    ShOpenFolderWindow,
    CertDigestDigest,
    CertSelectCertificate,
    DirectPlayCreate,
    DirectPlayEnumerateW,
    KerbLogon,
    KerbRetrieveTicket,
    NetGetAnyDcName,
    NetGetDcName,
    ShCreateLinks,
    ShNavigateToFavorite,
    NetWkstaSetInfo,
    X3dAudioCalculate,
    X3dAudioInitialize,
    Xact3CreateEngine,
    Xact3CreateEngineWithFlags,
    /// One vtable slot of a real XACT3 guest object (`IXACT3Engine`,
    /// `IXACT3SoundBank`, `IXACT3WaveBank`, `IXACT3Cue`, `IXACT3Wave`).
    /// `interface` is a `crate::xact::IFACE_*` id, `method` the vtable index
    /// (including the three `IUnknown` slots), and `x86_arg_bytes` the
    /// stdcall argument byte count the 32-bit dispatcher pops on return.
    /// See `crate::xact` and `dispatch::final_scraps`.
    Xact3Method {
        interface: u8,
        method: u16,
        x86_arg_bytes: u8,
    },
    /// One slot of the real `IWebBrowser2` browser-control vtable.
    /// See `dispatch::shdocvw`.
    WebBrowserMethod(crate::runtime::dispatch::shdocvw::WebBrowserMethod),
    /// One vtable slot of a real DirectPlay guest object: an
    /// `IDirectPlay8Address`, an `IDirectPlay8Peer`, or the legacy
    /// `IDirectPlay4` object returned by `DirectPlayCreate`.  `interface` is a
    /// `crate::dplay::IFACE_*` id, `method` the vtable index (including the
    /// three `IUnknown` slots), and `x86_arg_bytes` the stdcall argument byte
    /// count the 32-bit dispatcher pops on return.
    /// See `crate::dplay` and `dispatch::final_scraps`.
    Dplay8Method {
        interface: u8,
        method: u16,
        x86_arg_bytes: u8,
    },
    /// `DirectPlay8AddressCreate(iid, out, outer)` — the dpaddr.dll address
    /// factory handing out a real `IDirectPlay8Address` object.
    DirectPlay8AddressCreate,
    NtCreateFileMapping,
    NtCreateProcess,
    ImfAsyncResult,
    ImfGetService,
    BrowserServerEnum,
    CngAuditLog,
    GdipCreateGraphics,
    ActivateAudioInterfaceAsync,
    // ── IAudioClient / IAudioRenderClient methods of an activated audio
    //    endpoint (real host thunks; see `crate::audio_activation`) ──
    AudioActivationOperationQueryInterface,
    AudioActivationOperationGetActivateResult,
    AudioClientQueryInterface,
    AudioClientInitialize,
    AudioClientGetBufferSize,
    AudioClientGetStreamLatency,
    AudioClientGetCurrentPadding,
    AudioClientIsFormatSupported,
    AudioClientGetMixFormat,
    AudioClientGetDevicePeriod,
    AudioClientStart,
    AudioClientStop,
    AudioClientReset,
    AudioClientSetEventHandle,
    AudioClientGetService,
    AudioRenderClientQueryInterface,
    AudioRenderClientGetBuffer,
    AudioRenderClientReleaseBuffer,
    AudioClientIsOffloadCapable,
    AudioClientSetClientProperties,
    AudioClientGetBufferSizeLimits,
    AudioClientGetSharedModeEnginePeriod,
    AudioClientGetCurrentSharedModeEnginePeriod,
    AudioClientInitializeSharedAudioStream,
    // ── service objects returned by IAudioClient::GetService (real host
    //    thunks; see `crate::audio_activation`) ──
    AudioServiceQueryInterface,
    AudioClockGetFrequency,
    AudioClockGetPosition,
    AudioClockGetState,
    AudioSimpleVolumeSetMasterVolume,
    AudioSimpleVolumeGetMasterVolume,
    AudioSimpleVolumeSetMute,
    AudioSimpleVolumeGetMute,
    AudioStreamVolumeGetChannelCount,
    AudioStreamVolumeSetChannelVolume,
    AudioStreamVolumeGetChannelVolume,
    AudioStreamVolumeSetAllVolumes,
    AudioStreamVolumeGetAllVolumes,
    AudioSessionControlGetState,
    AudioSessionControlSetDisplayName,
    AudioSessionControlGetDisplayName,
    AudioSessionControlSetIconPath,
    AudioSessionControlGetIconPath,
    AudioSessionControlSetGroupingParam,
    AudioSessionControlGetGroupingParam,
    AudioSessionControlRegisterNotification,
    AudioSessionControlUnregisterNotification,
    AudioSessionControl2GetSessionIdentifier,
    AudioSessionControl2GetSessionInstanceIdentifier,
    AudioSessionControl2GetProcessId,
    AudioSessionControl2IsSystemSoundsSession,
    AudioSessionControl2SetDuckingPreference,
    AudioCaptureClientGetBuffer,
    AudioCaptureClientReleaseBuffer,
    AudioCaptureClientGetNextPacketSize,
    MsftEditRegisterClass,
    RichEditAnsiWndClass,
    NetServerGetInfo,
    DsBindToTopology,
    IPersistFile,
    IActiveScript,
    ID3d12Heap,
    ImfMediaSink,
    AdsBuildEnumerator,
    AdsGetObject,
    AdsOpenObject,
    CertSrvAdminGetCa,
    CertSrvAdminGetCert,
    CertSrvAdminSetCa,
    D3d10CreateDevice1,
    D3d10CreateDeviceAndSwapChain1,
    Dhcpv6ReleaseParams,
    Dhcpv6RenewParams,
    Dhcpv6RequestParams,
    GetdfDIJoystick,
    FwpsFilter,
    FwpsOpenToken,
    FwpsQueryTokenInformation,
    IeGetFrameComponent,
    IeGetWriteableHlink,
    IeHlink,
    LoadPerfCounterTextStringsW,
    SetServiceAsTrusted,
    UnloadPerfCounterTextStringsW,
    MsiFormatRecordW,
    MsiGetLastErrorRecord,
    MsiProcessMessage,
    ApplyPatchToFileExW,
    ApplyPatchToFileW,
    GetPatchFileSignature,
    PrintUiEntry,
    PrintUiToDevice,
    PrintUiToFile,
    SamCloseHandle,
    SamConnect,
    SamOpenDomain,
    ScGenerateRelativeName,
    ScRemoveAllPrivileges,
    ScSetSecurityDescriptor,
    RnrCancelQuery,
    RnrInitialize,
    RnrQuery,
    WinStationCloseServer,
    WinStationEnumerate,
    WinStationOpenServer,
    CreateFx,
    DirectSoundCreate8,
    DirectSoundEnumerateW,
    CryptUiDlgCertMgr,
    CryptUiDlgSelectCertificateW,
    CryptUiDlgSelectStoreW,
    CryptUiDlgViewCertificateW,
    WicCreateImagingFactory,
    WicCreateImagingFactoryProxy,
    WicCreateBitmapProxy,
    WicCreateBitmapScalerProxy,
    WicCreateBitmapClipperProxy,
    WicCreateBitmapFlipRotatorProxy,
    WicCreateFormatConverterProxy,
    WicCreatePaletteProxy,
    WicCreateStreamProxy,
    WicCreateColorContextProxy,
    WicCreateBitmapFromSectionProxy,
    WicCreateComponentInfo,
    WicGetMetadataContentSize,
    WicMapSchemaToName,
    WicMatchMetadataContent,
    WicSerializeMetadataContent,
    WicFactoryCreateDecoderFromFilename,
    WicFactoryCreateDecoderFromStream,
    WicFactoryCreateDecoderFromFileHandle,
    WicFactoryCreateComponentInfo,
    WicFactoryCreateDecoder,
    WicFactoryCreateEncoder,
    WicFactoryCreatePalette,
    WicFactoryCreateFormatConverter,
    WicFactoryCreateBitmapScaler,
    WicFactoryCreateBitmapClipper,
    WicFactoryCreateBitmapFlipRotator,
    WicFactoryCreateStream,
    WicFactoryCreateColorContext,
    WicFactoryCreateColorTransformer,
    WicFactoryCreateBitmap,
    WicFactoryCreateBitmapFromSource,
    WicFactoryCreateBitmapFromSourceRect,
    WicFactoryCreateBitmapFromMemory,
    WicFactoryCreateBitmapFromHbitmap,
    WicFactoryCreateBitmapFromHicon,
    WicFactoryCreateComponentEnumerator,
    WicFactoryCreateFastMetadataEncoderFromFrameDecode,
    WicFactoryCreateFastMetadataEncoderFromQueryWriter,
    WicFactoryCreateQueryWriter,
    WicFactoryCreateQueryWriterFromReader,
    WicSourceGetSize,
    WicSourceGetPixelFormat,
    WicSourceGetResolution,
    WicSourceCopyPalette,
    WicSourceCopyPixels,
    WicBitmapLock,
    WicBitmapLockGetSize,
    WicBitmapLockGetStride,
    WicBitmapLockGetPixelFormat,
    WicBitmapLockGetDataPointer,
    WicBitmapUnlock,
    WicLockRelease,
    WicBitmapSetPalette,
    WicBitmapSetResolution,
    WicScalerInitialize,
    WicScalerGetScaledWidth,
    WicScalerGetScaledHeight,
    WicScalerGetInterpolationMode,
    WicScalerSetInterpolationMode,
    WicClipperInitialize,
    WicClipperGetClipRect,
    WicClipperSetClipRect,
    WicFlipRotatorInitialize,
    WicFlipRotatorGetTransform,
    WicFormatConverterInitialize,
    WicFormatConverterCanConvert,
    WicFormatConverterGetPixelFormat,
    WicFormatConverterSetPixelFormat,
    WicPaletteInitializeCustom,
    WicPaletteInitializePredefined,
    WicPaletteInitializeFromBitmap,
    WicPaletteInitializeFromPalette,
    WicPaletteGetType,
    WicPaletteGetColorCount,
    WicPaletteGetColors,
    WicPaletteIsBlackWhite,
    WicPaletteIsGrayscale,
    WicPaletteHasAlpha,
    WicStreamInitializeFromIStream,
    WicStreamInitializeFromFilename,
    WicStreamInitializeFromMemory,
    WicStreamInitializeFromIStreamRegion,
    WicColorContextInitializeFromFilename,
    WicColorContextInitializeFromMemory,
    WicColorContextGetProfileBytes,
    WicColorContextGetType,
    WicColorContextGetExifColorSpace,
    WicColorContextSetExifColorSpace,
    WicComponentInfoGetComponentType,
    WicComponentInfoGetClsid,
    WicComponentInfoGetSigningStatus,
    WicComponentInfoGetAuthor,
    WicComponentInfoGetVendorGuid,
    WicComponentInfoGetVersion,
    WicComponentInfoGetSpecVersion,
    WicComponentInfoGetFriendlyName,
    WicDecoderQueryCapability,
    WicDecoderInitialize,
    WicDecoderGetContainerFormat,
    WicDecoderGetFrameCount,
    WicDecoderGetFrame,
    WicDecoderUnsupported,
    WicEncoderInitialize,
    WicEncoderCreateNewFrame,
    WicEncoderCommit,
    WicEncoderGetContainerFormat,
    WicEncoderUnsupported,
    WicFrameEncodeInitialize,
    WicFrameEncodeSetSize,
    WicFrameEncodeSetResolution,
    WicFrameEncodeSetPixelFormat,
    WicFrameEncodeWritePixels,
    WicFrameEncodeWriteSource,
    WicFrameEncodeCommit,
    WicFrameEncodeUnsupported,
    CoMarshalInterThreadInterfaceInStream,
    CoGetInterfaceAndReleaseStream,
    CreateBindCtx,
    MkParseDisplayName,
    OleDuplicateData,
    OleSetMenuDescriptor,
    CoGetClassObjectFromUrl,
    CoGetInstanceFromFile,
    CoGetInstanceFromIStorage,
    CoInstall,
    CoIsHandlerConnected,
    SysStringByteLen,
    SafeArrayGetDim,
    BstrUserSize,
    BstrUserMarshal,
    BstrUserUnmarshal,
    BstrUserFree,
    LHashValOfNameSys,
    VariantChangeTypeEx,
    VariantCopyInd,
    MfStartup,
    MfShutdown,
    MfRequireProtectedEnvironment,
    MfGetService,
    MfAddPeriodicCallback,
    MfCancelPeriodicCallback,
    MfGetSystemTime,
    MfCreateAttributes,
    MfCreateMediaType,
    MfCreateMemoryBuffer,
    MfCreateSample,
    MfCreateEventQueue,
    MfCreatePresentationClock,
    MfCreateTopology,
    MfCreateTopologyNode,
    MfCreateSourceResolver,
    MfCreateMediaSession,
    MfCreateSourceReaderFromUrl,
    MfCreateSourceReaderFromByteStream,
    MfCreateSinkWriterFromUrl,
    MfCreatePresentationDescriptor,
    MfCreateMfByteStreamOnStream,
    MfCreateMediaBufferFromMediaType,
    MfCreateDxgiDeviceManager,
    MfDxgiDeviceManagerResetDevice,
    MfDxgiDeviceManagerOpenDeviceHandle,
    MfDxgiDeviceManagerCloseDeviceHandle,
    MfDxgiDeviceManagerTestDevice,
    MfDxgiDeviceManagerLockDevice,
    MfDxgiDeviceManagerUnlockDevice,
    MfDxgiDeviceManagerGetVideoService,
    MftEnumEx,
    MfEnumDeviceSources,
    MfCreateSinkWriterFromMediaSink,
    MfCreateSourceReaderFromMfByteStream,
    MfAttrGetCount,
    MfAttrGetItemByIndex,
    MfAttrGetUint32,
    MfAttrGetUint64,
    MfAttrGetDouble,
    MfAttrGetGuid,
    MfAttrGetStringLength,
    MfAttrGetString,
    MfAttrGetBlobSize,
    MfAttrGetBlob,
    MfAttrSetUint32,
    MfAttrSetUint64,
    MfAttrSetDouble,
    MfAttrSetGuid,
    MfAttrSetString,
    MfAttrSetBlob,
    MfAttrDeleteItem,
    MfMediaTypeGetMajorType,
    MfMediaTypeIsCompressedFormat,
    MfMediaTypeIsEqual,
    MfMediaTypeGetRepresentation,
    MfMediaTypeFreeRepresentation,
    MfBufferGetMaxLength,
    MfBufferLock,
    MfBufferUnlock,
    MfBufferGetCurrentLength,
    MfBufferSetCurrentLength,
    MfSampleGetBufferCount,
    MfSampleGetBufferByIndex,
    MfSampleAddBuffer,
    MfSampleRemoveBufferByIndex,
    MfSampleRemoveAllBuffers,
    MfSampleGetSampleTime,
    MfSampleSetSampleTime,
    MfSampleGetSampleDuration,
    MfSampleSetSampleDuration,
    MfEventQueueGetEvent,
    MfEventQueueQueueEvent,
    MfClockGetTime,
    MfClockStart,
    MfClockStop,
    MfSessionGetClock,
    MfRateControlSetRate,
    MfRateControlGetRate,
    MfRateSupportGetSlowestRate,
    MfRateSupportGetFastestRate,
    MfRateSupportIsRateSupported,
    MfSessionStart,
    MfSessionPause,
    MfSessionStop,
    MfSessionClose,
    MfSessionShutdown,
    MfSourceReaderGetCurrentMediaType,
    MfSourceReaderGetNativeMediaType,
    MfSourceReaderReadSample,
    MfSourceReaderGetStreamSelection,
    MfSourceReaderSetStreamSelection,
    MfSourceReaderSetCurrentMediaType,
    MfSourceReaderSetCurrentPosition,
    MfSourceReaderFlush,
    MfSourceReaderGetServiceForStream,
    MfSourceReaderGetPresentationAttribute,
    MfSinkWriterAddStream,
    MfSinkWriterBeginWriting,
    MfSinkWriterWriteSample,
    MfSinkWriterEndWriting,
    MfByteStreamGetCurrentPosition,
    MfByteStreamRead,
    MfByteStreamGetLength,
    MfByteStreamGetCapabilities,
    MfByteStreamSetLength,
    MfByteStreamSetCurrentPosition,
    MfByteStreamIsEndOfStream,
    MfByteStreamWrite,
    MfByteStreamBeginRead,
    MfByteStreamEndRead,
    MfByteStreamBeginWrite,
    MfByteStreamEndWrite,
    MfByteStreamSeek,
    MfByteStreamFlush,
    MfByteStreamClose,
    MfTopologyAddNode,
    MfTopologyGetNodeCount,
    MfTopologyNodeGetObject,
    MfTopologyNodeSetObject,
    MfPresentationDescriptorGetStreamDescriptorCount,
    MfEventGetType,
    MfSessionSetTopology,
    MfSessionGetSessionCapabilities,
    MfSessionGetFullTopology,
    MfSessionGetDescriptorFromTopology,
    MfSinkWriterSetInputMediaType,
    MfSinkWriterFlush,
    MfSinkWriterGetStatistics,
    MfSinkWriterSendStreamSample,
    MfSinkWriterNotifyEndOfSegment,
    MfSinkWriterGetServiceForStream,
    IDispatchGetTypeInfoCount,
    IDispatchGetTypeInfo,
    MfMediaSourceGetCharacteristics,
    MfMediaSourceCreatePresentationDescriptor,
    MfMediaSourceStart,
    MfMediaSourceStop,
    MfMediaSourcePause,
    MfMediaSourceShutdown,
    MfMediaSourceGetEvent,
    MfMediaSourceBeginGetEvent,
    MfMediaSourceEndGetEvent,
    MfMediaSourceQueueEvent,
    MfMediaSourceCancelGetEvent,
    MfMediaSourceGetSourceAttributes,
    MfMediaSourceGetStreamAttributes,
    MfMediaSourceSetD3dManager,
    MfPresentationDescriptorGetStreamDescriptorByIndex,
    MfPresentationDescriptorSelectStream,
    MfPresentationDescriptorDeselectStream,
    MfPresentationDescriptorClone,
    MfStreamDescriptorGetStreamIdentifier,
    MfStreamDescriptorGetMediaTypeHandler,
    MfMediaTypeHandlerIsMediaTypeSupported,
    MfMediaTypeHandlerGetMediaTypeCount,
    MfMediaTypeHandlerGetMediaTypeByIndex,
    MfMediaTypeHandlerSetCurrentMediaType,
    MfMediaTypeHandlerGetCurrentMediaType,
    MfMediaTypeHandlerGetMajorType,
    MfEventGetExtendedType,
    MfEventGetStatus,
    MfEventGetValue,
    MfAsyncResultGetState,
    MfAsyncResultGetStatus,
    MfAsyncResultSetStatus,
    MfAsyncResultGetObject,
    MfAsyncResultGetCallback,
    MfCreateFile,
    MfCreateTempFile,
    MfMetadataSetLanguage,
    MfMetadataGetLanguage,
    MfMetadataGetAllLanguages,
    MfMetadataDeleteLanguage,
    MfMetadataSetProperty,
    MfMetadataGetProperty,
    MfMetadataDeleteProperty,
    MfMetadataGetAllPropertyNames,
    MfObjectQueryInterface,
    MfSourceResolverBeginFromUrl,
    MfSourceResolverBeginFromByteStream,
    MfSourceResolverEndFromUrl,
    MfSourceResolverEndFromByteStream,
    MfSourceResolverCancel,
    MfSourceResolverCreateObjectFromUrl,
    MfSourceResolverCreateObjectFromByteStream,
    MftStreamAttributes,
    MftFixedStreams,
    MftProcessEvent,
    MfAttrGetItem,
    MfAttrGetItemType,
    MfAttrCompareItem,
    MfAttrCompare,
    MfAttrGetAllocatedString,
    MfAttrGetAllocatedBlob,
    MfAttrGetUnknown,
    MfAttrSetItem,
    MfAttrSetUnknown,
    MfAttrDeleteAllItems,
    MfAttrLockStore,
    MfAttrUnlockStore,
    MfAttrCopyAllItems,
    MfSampleSetSampleFlags,
    MfSampleGetSampleFlags,
    MfSampleGetTotalLength,
    MfSampleCopyToBuffer,
    MfSampleConvertToContiguousBuffer,
    MfActivateGetCount,
    MfActivateGetItem,
    MfActivateGetGuid,
    MfActivateGetString,
    MfActivateActivateObject,
    MfActivateShutdownObject,
    MfTransformGetStreamLimits,
    MfTransformGetStreamCounts,
    MfTransformGetStreamIds,
    MfTransformGetStreamInfo,
    MfTransformGetAttributes,
    MfTransformGetInputAvailableType,
    MfTransformGetOutputAvailableType,
    MfTransformSetInputType,
    MfTransformSetOutputType,
    MfTransformGetInputCurrentType,
    MfTransformGetOutputCurrentType,
    MfTransformGetInputStatus,
    MfTransformGetOutputStatus,
    MfTransformProcessInput,
    MfTransformProcessOutput,
    MfTransformProcessMessage,
    MftTransformUnsupported,
    GlBegin,
    GlBindTexture,
    GlBlendFunc,
    GlClear,
    GlClearColor,
    GlColor3f,
    GlColor4f,
    GlColorPointer,
    GlCullFace,
    GlDeleteTextures,
    GlDepthFunc,
    GlDisable,
    GlDisableClientState,
    GlDrawArrays,
    GlDrawElements,
    GlEnable,
    GlEnableClientState,
    GlEnd,
    GlFinish,
    GlFlush,
    GlFogf,
    GlFogi,
    GlFrontFace,
    GlGenTextures,
    GlGetError,
    GlGetString,
    GlHint,
    GlLightfv,
    GlLoadIdentity,
    GlMaterialfv,
    GlMatrixMode,
    GlNormalPointer,
    GlOrtho,
    GlPopMatrix,
    GlPushMatrix,
    GlReadPixels,
    GlRotatef,
    GlScalef,
    GlShadeModel,
    GlTexCoord2f,
    GlTexCoordPointer,
    GlTexImage2D,
    GlTexParameterf,
    GlTexParameteri,
    GlTranslatef,
    GlVertex2f,
    GlVertex3f,
    GlVertexPointer,
    GlViewport,
    GluBuild2DMipmaps,
    GluCylinder,
    GluDeleteQuadric,
    GluDisk,
    GluErrorString,
    GluLookAt,
    GluNewQuadric,
    GluNewTess,
    GluOrtho2D,
    GluPartialDisk,
    GluPerspective,
    GluPickMatrix,
    GluProject,
    GluScaleImage,
    GluSphere,
    GluTessBeginPolygon,
    GluTessEndPolygon,
    GluTessVertex,
    GluUnProject,
    WglChoosePixelFormat,
    WglCreateContext,
    WglDeleteContext,
    WglDescribePixelFormat,
    WglGetPixelFormat,
    WglGetProcAddress,
    WglMakeCurrent,
    WglSetPixelFormat,
    WglSwapBuffers,
}
