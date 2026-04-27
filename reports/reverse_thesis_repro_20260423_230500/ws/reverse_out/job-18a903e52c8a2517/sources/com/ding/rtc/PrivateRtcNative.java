package com.ding.rtc;

import android.graphics.Matrix;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcNative {
    static native int nativeAudioAddExternalAudioRenderSource(long nativePtr, String uniqueId);

    static native int nativeAudioAddExternalAudioSource(long nativePtr, String uniqueId);

    static native String nativeAudioCreateExternalAudioSource(long nativePtr, int sampleRate);

    static native void nativeAudioDestroyExternalAudioSource(long nativePtr, String uniqueId);

    static native int nativeAudioDeviceEnableAudioLevelObserver(long nativePtr, int type, boolean enable);

    static native int nativeAudioDeviceEnableBuiltInAEC(long nativePtr, boolean enable);

    static native int nativeAudioDeviceEnableBuiltInAGC(long nativePtr, boolean enable);

    static native int nativeAudioDeviceEnableBuiltInNS(long nativePtr, boolean enable);

    static native int nativeAudioDeviceEnableHardwareAec(long nativePtr, boolean enable);

    static native int nativeAudioDeviceEnableSpeakerphone(long nativePtr, boolean enable);

    static native int nativeAudioDeviceGetAudioDeviceOptionIndex(long nativePtr);

    static native int nativeAudioDeviceGetAudioDeviceOptionSize(long nativePtr);

    static native int nativeAudioDeviceGetCurrentPlayoutLevel(long nativePtr);

    static native int nativeAudioDeviceGetCurrentRecordingLevel(long nativePtr);

    static native int nativeAudioDeviceGetPlayoutDeviceVolume(long nativePtr);

    static native int nativeAudioDeviceGetRecordingDeviceVolume(long nativePtr);

    static native int nativeAudioDeviceGetSystemPlayoutDeviceVolume(long nativePtr);

    static native int nativeAudioDeviceGetSystemRecordingDeviceVolume(long nativePtr);

    static native int nativeAudioDeviceInitAudioOptions(long nativePtr, boolean useServerConfig, boolean bluetooth, boolean useMusicMode, String preferOption);

    static native boolean nativeAudioDeviceIsBuiltInAECAvailable(long nativePtr);

    static native boolean nativeAudioDeviceIsBuiltInAGCAvailable(long nativePtr);

    static native boolean nativeAudioDeviceIsBuiltInNSAvailable(long nativePtr);

    static native boolean nativeAudioDeviceIsPlaying(long nativePtr);

    static native boolean nativeAudioDeviceIsPlayoutDeviceMuteAvailable(long nativePtr);

    static native boolean nativeAudioDeviceIsPlayoutDeviceMuted(long nativePtr);

    static native boolean nativeAudioDeviceIsRecording(long nativePtr);

    static native boolean nativeAudioDeviceIsRecordingDeviceMuted(long nativePtr);

    static native boolean nativeAudioDeviceIsSpeakerphoneEnabled(long nativePtr);

    static native boolean nativeAudioDeviceIsStereoPlayout(long nativePtr);

    static native boolean nativeAudioDeviceIsStereoPlayoutAvailable(long nativePtr);

    static native boolean nativeAudioDeviceIsStereoRecording(long nativePtr);

    static native boolean nativeAudioDeviceIsStereoRecordingAvailable(long nativePtr);

    static native int nativeAudioDevicePlayTone(long nativePtr, int type);

    static native int nativeAudioDevicePlayoutDelay(long nativePtr);

    static native int nativeAudioDeviceSetBuiltInAudioProcessingConfig(long nativePtr, int config);

    static native int nativeAudioDeviceSetDefaultAudioRouteToSpeakerphone(long nativePtr, boolean defaultToSpeakerphone);

    static native int nativeAudioDeviceSetPlayoutDeviceMute(long nativePtr, boolean mute);

    static native int nativeAudioDeviceSetPlayoutDevicePan(long nativePtr, int type);

    static native int nativeAudioDeviceSetPlayoutDeviceVolume(long nativePtr, int volume);

    static native int nativeAudioDeviceSetRecordingDataMute(long nativePtr, boolean mute);

    static native int nativeAudioDeviceSetRecordingDeviceMute(long nativePtr, boolean mute);

    static native int nativeAudioDeviceSetRecordingDeviceVolume(long nativePtr, int volume);

    static native int nativeAudioDeviceSetStereoPlayout(long nativePtr, boolean enable);

    static native int nativeAudioDeviceSetStereoRecording(long nativePtr, boolean enable);

    static native int nativeAudioDeviceSetSystemPlayoutDeviceVolume(long nativePtr, int volume);

    static native int nativeAudioDeviceSetSystemRecordingDeviceVolume(long nativePtr, int volume);

    static native int nativeAudioDeviceStartPlayingAudioFile(long nativePtr, String fileName, int type, int numChannels, int sampleRate, float volumeScaling);

    static native int nativeAudioDeviceStartPlayout(long nativePtr);

    static native int nativeAudioDeviceStartPlayoutDeviceTest(long nativePtr, String path);

    static native int nativeAudioDeviceStartRecording(long nativePtr);

    static native int nativeAudioDeviceStartRecordingDeviceTest(long nativePtr);

    static native int nativeAudioDeviceStopPlayingAudioFile(long nativePtr, int id);

    static native int nativeAudioDeviceStopPlayout(long nativePtr);

    static native int nativeAudioDeviceStopPlayoutDeviceTest(long nativePtr);

    static native int nativeAudioDeviceStopRecording(long nativePtr);

    static native int nativeAudioDeviceStopRecordingDeviceTest(long nativePtr);

    static native int nativeAudioDeviceSwitchAudioDeviceOption(long nativePtr, int index);

    static native int nativeAudioExternalDeliverFrame(long nativePtr, String uniqueId, byte[] pcmData, int numSamples, int bytesPerSample, int numChannels, int samplesPerSec, short recDelayMs);

    static native boolean nativeAudioExternalMaybeOverflow(long nativePtr, String uniqueId, int numOf10MsData);

    static native void nativeAudioProcessBypassAll(long nativePtr, boolean bypass);

    static native void nativeAudioProcessEnableAutoGainControl(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableBeamformingProcess(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableEchoCancellation(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableEhanceNoiseSuppression(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableHowlingDetection(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableLighting(long nativePtr, boolean enable, String path);

    static native void nativeAudioProcessEnableMicVolAdjust(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableMusicDetection(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableMusicMode(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableNoiseSuppression(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableRenderIntelligibility(long nativePtr, boolean enable);

    static native void nativeAudioProcessEnableVadReport(long nativePtr, boolean enable);

    static native boolean nativeAudioProcessIsBeamformingProcessSupported(long nativePtr);

    static native void nativeAudioProcessMuteRender(long nativePtr, boolean mute);

    static native int nativeAudioRemoveExternalAudioRenderSource(long nativePtr, String uniqueId);

    static native int nativeAudioRemoveExternalAudioSource(long nativePtr, String uniqueId);

    static native long nativeCreate(String extras);

    static native String nativeCreateLocalMediaTrack(long nativePtr, int kind, PrivateRtcModelTrackListener listener);

    static native void nativeDestroy(long ptr);

    static native String nativeGetErrorDescription(int errorCode);

    static native String nativeGetLogDirPath();

    static native void nativeGetParticipantsAndStreams(long nativePtr, List<String> participantIds, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native String nativeGetSdkBuild();

    static native String nativeGetSdkVersion();

    static native boolean nativeIsCameraExposurePointSupported(long nativePtr);

    static native boolean nativeIsCameraFocusPointSupported(long nativePtr);

    static native boolean nativeIsCameraOn(long nativePtr);

    static native void nativeJoinChannel(long nativePtr, PrivateRtcModelChannelConfig channelConfig, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native void nativeLeaveChannel(long nativePtr, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native int nativeNotifyParticipantsLeft(long nativePtr, List<String> participantIds);

    static native void nativeParticipantSetObserver(long nativePtr, String uniqueId, PrivateRtcModelParticipantListener listener);

    static native void nativePublish(long nativePtr, String trackUniqueId, PrivateRtcModelPublishOptions op, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native void nativeRenderClearContent(long nativePtr, String uniqueId, String renderUniqueId);

    static native void nativeRenderSetBgColor(long nativePtr, String uniqueId, String renderUniqueId, int color);

    static native void nativeRenderSetMirror(long nativePtr, String uniqueId, String renderUniqueId, boolean mirror);

    static native void nativeRenderSetMode(long nativePtr, String uniqueId, String renderUniqueId, int mode);

    static native void nativeRenderSetRotation(long nativePtr, String uniqueId, String renderUniqueId, int rotation);

    static native void nativeRenderZoomAndTranslate(long nativePtr, String uniqueId, String renderUniqueId, Matrix matrix);

    static native int nativeScreenManagerSetScreenSource(long nativePtr, int mode);

    static native void nativeSetAudioDeviceEnableAnalogObserver(long nativePtr, boolean enable);

    static native void nativeSetAudioDeviceEnableFileObserver(long nativePtr, boolean enable);

    static native void nativeSetAudioDeviceEnableLevelObserver(long nativePtr, boolean enable);

    static native void nativeSetAudioDeviceEnableObserver(long nativePtr, boolean enable);

    static native boolean nativeSetAudioDeviceIsPlayoutDeviceVolumeAvailable(long nativePtr);

    static native boolean nativeSetAudioDeviceIsRecordingDeviceMuteAvailable(long nativePtr);

    static native boolean nativeSetAudioDeviceIsRecordingDeviceVolumeAvailable(long nativePtr);

    static native void nativeSetAudioDeviceManagerObserver(long nativePtr, PrivateRtcModelEngineAudioMgrListener audioListener);

    static native int nativeSetAudioProfile(long nativePtr, int audioProfile, int audioScene);

    static native int nativeSetCameraExposurePoint(long nativePtr, float x, float y);

    static native int nativeSetCameraFlash(long nativePtr, boolean enabled);

    static native int nativeSetCameraFocusPoint(long nativePtr, float x, float y);

    static native int nativeSetCameraZoom(long nativePtr, float zoom);

    static native int nativeSetCurrentCameraDirection(long nativePtr, int value);

    static native void nativeSetDeviceOrientationMode(long nativePtr, int orientation);

    static native void nativeSetEngineObserver(long nativePtr, PrivateRtcModelEngineListener listener);

    static native int nativeSetLogDirPath(String path);

    static native int nativeSetLogLevel(int level);

    static native void nativeSetVideoDeviceManagerObserver(long nativePtr, PrivateRtcModelEngineVideoMgrListener dRtcVideoDeviceManager);

    static native int nativeStartPreview(long nativePtr);

    static native int nativeStopPreview(long nativePtr);

    static native void nativeSubscribe(long nativePtr, String trackUniqueId, PrivateRtcModelSubscribeOptions op, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native int nativeSwitchCamera(long nativePtr);

    static native void nativeTrackAddAttribute(long nativePtr, String uniqueId, String name, String value);

    static native void nativeTrackAddVideoSink(long nativePtr, String uniqueId);

    static native void nativeTrackAttachVideoRender(long nativePtr, String uniqueId, String renderUniqueId, PrivateRtcModelRenderConfig renderConfig);

    static native void nativeTrackDetachAllVideoRender(long nativePtr, String uniqueId);

    static native void nativeTrackDetachVideoRender(long nativePtr, String uniqueId, String renderUniqueId);

    static native int nativeTrackEnableBackground(long nativePtr, String uniqueId, boolean enabled, PrivateRtcModelVideoVirtualBackgroundParams params);

    static native int nativeTrackEnableBeautyFace(long nativePtr, String uniqueId, boolean enabled, PrivateRtcModelVideoBeautyFaceParams params);

    static native int nativeTrackEnableExternalVideoSource(long nativePtr, String uniqueId, boolean enabled);

    static native int nativeTrackEnableVideoAutoFraming(long nativePtr, String uniqueId, boolean enabled, PrivateRtcModelVideoAutoFramingParams params);

    static native int nativeTrackEnableVideoDenoise(long nativePtr, String uniqueId, boolean enabled, PrivateRtcModelVideoDenoiseParams params);

    static native int nativeTrackEnableVideoEnhance(long nativePtr, String uniqueId, boolean enabled, PrivateRtcModelVideoEnhanceParams params);

    static native String nativeTrackGetParticipantId(long nativePtr, String uniqueId);

    static native String nativeTrackGetSessionId(long nativePtr, String uniqueId);

    static native String nativeTrackGetStreamId(long nativePtr, String uniqueId);

    static native int nativeTrackGetTrackKind(long nativePtr, String uniqueId);

    static native String nativeTrackGetUserId(long nativePtr, String uniqueId);

    static native PrivateRtcModelTrackVideoResolution nativeTrackGetVideoResolution(long nativePtr, String uniqueId);

    static native int nativeTrackGetVolume(long nativePtr, String uniqueId);

    static native int nativeTrackId(long nativePtr, String uniqueId);

    static native boolean nativeTrackIsMuted(long nativePtr, String uniqueId);

    static native void nativeTrackMute(long nativePtr, String uniqueId);

    static native int nativeTrackPauseVideo(long nativePtr, String uniqueId, String imagePath);

    static native int nativeTrackPushExternalVideoFrame(long nativePtr, String uniqueId, PrivateRtcModelVideoFrame videoFrame);

    static native void nativeTrackRemoveAttribute(long nativePtr, String uniqueId, String name);

    static native void nativeTrackRemoveVideoSink(long nativePtr, String uniqueId);

    static native int nativeTrackResumeVideo(long nativePtr, String uniqueId);

    static native void nativeTrackSetObserver(long nativePtr, String uniqueId, PrivateRtcModelTrackListener listener);

    static native int nativeTrackSetVideoEncodingParameters(long nativePtr, String uniqueId, PrivateRtcModelTrackPublicationOptions config);

    static native int nativeTrackSetVolumeGain(long nativePtr, String uniqueId, float gain);

    static native void nativeTrackSnapshotVideo(long nativePtr, String uniqueId, PrivateRtcModelSnapshotOption option, PrivateRtcModelOnSnapshotSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native void nativeTrackUnmute(long nativePtr, String uniqueId);

    static native int nativeTrackUpdateVideoSubscription(long nativePtr, String uniqueId, PrivateRtcModelTrackSubscriptionOptions config);

    static native void nativeUnPublish(long nativePtr, String trackUniqueId, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native void nativeUnSubscribe(long nativePtr, String trackUniqueId, PrivateRtcModelOnSuccess onSuccess, PrivateRtcModelOnFailure onFail);

    static native void nativeUpdateGraySwitchConfig(long nativePtr, String key, boolean value);

    PrivateRtcNative() {
    }
}
