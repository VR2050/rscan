package com.ding.rtc;

import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import android.util.Log;
import android.view.SurfaceView;
import android.view.TextureView;
import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.http.FileUtil;
import com.ding.rtc.model.RtcEngineAudioRawFrame;
import com.ding.rtc.model.RtcEngineRawDataFrame;
import com.ding.rtc.monitor.DeviceMonitor;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONException;
import org.json.JSONObject;
import org.webrtc.mozi.Camera1Enumerator;
import org.webrtc.mozi.CameraEnumerator;
import org.webrtc.mozi.ContextUtils;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.video.view.RTCSurfaceView;
import org.webrtc.mozi.video.view.RTCTextureView;
import org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher;
import org.webrtc.mozi.voiceengine.device.AudioRouteType;

/* JADX INFO: loaded from: classes.dex */
class RtcEngineImpl extends DingRtcEngine {
    private static final String TAG = RtcEngineImpl.class.getSimpleName();
    private final Object mEngineLock = new Object();
    private final RtcEngineVideoCallbackObserver mExternVideoSampleObserver;
    private final RtcEngineAudioCallbackObserver mExternalAudioFrameObserver;
    private long mNativePtr;
    private final RtcEngineEventListener mRtcEngineEventListener;
    private final RtmClientImpl mRtmClientImpl;
    private final DingRtcEngineWhiteboardManager mWhiteboardManagerImpl;

    static native String nativeErrorDescription(int errorCode);

    static native String nativeGetSDKBuild();

    static native String nativeGetSDKVersion();

    static native int nativeSetLogDirPath(String path);

    static native int nativeSetLogLevel(int level);

    native long nativeCreate(String extras, RtcEngineEventListener listener);

    native int nativeCreateAudioMixing(long instance, int id, String filePath);

    native void nativeDestroy(long instance);

    native int nativeDestroyAudioMixing(long instance, int id);

    native int nativeDismissGroup(long instance, String groupId);

    native int nativeEnableAudioFrameObserver2(long instance, boolean enable, int position);

    native int nativeEnableAudioFrameObserver3(long handle, boolean enabled, int position, int sampleRate, int channels, boolean readOnly);

    native int nativeEnableAudioVolumeIndication(long instance, int interval, int smooth, int reportVad);

    native int nativeEnableBeautyFace(long instance, boolean enable, String resourcePath, boolean enableSkinBuffing, float skinBuffingFactor, float skinSharpenFactor, boolean enableSkinWhitening, float skinWhitingFactor, boolean enableFilter, String filterPath);

    native int nativeEnableCustomAudioCapture(long instance, boolean enable);

    native int nativeEnableCustomAudioRender(long instance, boolean enable);

    native int nativeEnableLocalVideo(long instance, boolean enabled);

    native int nativeEnableSpeakerphone(long instance, boolean enable);

    native int nativeEnableVideoSampleObserver(long instance, boolean enable, int position);

    native int nativeEnableVirtualBackground(long instance, boolean enable, int mode, String bgFilePath);

    native long nativeGetAudioMixingCurrentPosition(long instance, int id);

    native long nativeGetAudioMixingDuration(long instance, int id);

    native int nativeGetAudioMixingPlayoutVolume(long instance, int id);

    native int nativeGetAudioMixingPublishVolume(long instance, int id);

    native int nativeGetAudioMixingVolume(long instance, int id);

    native float nativeGetCameraMaxExposureCompensation(long instance);

    native float nativeGetCameraMinExposureCompensation(long instance);

    native int nativeGetCurrentCameraDirection(long instance);

    native String nativeGetCurrentCameraID(long instance);

    native String nativeGetCurrentCameraName(long instance);

    native int nativeGetCurrentConnectionStatus(long instance);

    native String nativeGetCurrentSubscribedAudio(long instance);

    native int nativeGetCustomAudioRenderFrame(long instance, RtcEngineAudioRawFrame frame);

    native String[] nativeGetOnlineRemoteUsers(long instance);

    native int nativeGetPlayoutSignalVolume(long instance);

    native int nativeGetRecordingSignalVolume(long instance);

    native DingRtcRemoteUserInfo nativeGetUserInfo(long instance, String uid);

    native boolean nativeIsCameraAutoFocusFaceModeSupported(long instance);

    native boolean nativeIsCameraExposurePointSupported(long instance);

    native boolean nativeIsCameraFocusPointSupported(long instance);

    native boolean nativeIsCameraOn(long instance);

    native boolean nativeIsInCall(long instance);

    native boolean nativeIsLocalAudioStreamPublished(long instance);

    native boolean nativeIsLocalVideoStreamPublished(long instance);

    native boolean nativeIsScreenSharePublished(long instance);

    native boolean nativeIsSpeakerphoneEnabled(long instance);

    native boolean nativeIsUserOnline(long instance, String uid);

    native int nativeJoinChannel(long instance, DingRtcAuthInfo authInfo, String userName);

    native int nativeJoinGroup(long instance, String groupId, String usrData);

    native int nativeLeaveChannel(long instance, long timeout);

    native int nativeLeaveGroup(long instance, String groupId);

    native int nativeMixAudioToGroup(long instance, boolean mix, String groupId);

    native int nativeMuteLocalAudio(long instance, boolean mute);

    native int nativeMuteLocalCamera(long instance, boolean mute, int videoTrack);

    native int nativeMuteLocalMic(long instance, boolean mute, int mode);

    native int nativeMuteRecordingSignal(long instance, boolean mute);

    native int nativeMuteRemoteAudio(long instance, String uid, boolean mute);

    native int nativePauseAudioMixing(long instance, int id);

    native int nativePublishLocalAudioStream(long instance, boolean enabled);

    native int nativePublishLocalVideoStream(long instance, boolean enabled);

    native int nativePushExternalAudioFrame(long instance, RtcEngineAudioRawFrame frame);

    native int nativePushExternalAudioRenderFrame(long instance, RtcEngineAudioRawFrame frame);

    native int nativePushExternalVideoFrame(long instance, RtcEngineRawDataFrame frame, int track);

    native int nativeRegisterAudioFrameObserver(long instance, RtcEngineAudioCallbackObserver observer);

    native int nativeRegisterVideoCallback(long instance, RtcEngineVideoCallbackObserver observer);

    native int nativeResumeAudioMixing(long instance, int id);

    native int nativeSendCustomAudioCaptureFrame(long instance, RtcEngineAudioRawFrame frame);

    native int nativeSendMediaExtensionMsg(long instance, byte[] message, int repeatCount);

    native int nativeSetAudioDenoise(long nativePtr, int mode);

    native int nativeSetAudioMixingPlayoutVolume(long instance, int id, int volume);

    native int nativeSetAudioMixingPosition(long instance, int id, long position);

    native int nativeSetAudioMixingPublishVolume(long instance, int id, int volume);

    native int nativeSetAudioMixingVolume(long instance, int id, int volume);

    native int nativeSetAudioProfile(long instance, int profile, int scene);

    native int nativeSetCameraAutoFocusFaceModeEnabled(long instance, boolean enable);

    native int nativeSetCameraCapturerConfiguration(long instance, int preference, int cameraDirection);

    native int nativeSetCameraExposureCompensation(long instance, float value);

    native int nativeSetCameraExposurePoint(long instance, float x, float y);

    native int nativeSetCameraFlash(long instance, boolean flash);

    native int nativeSetCameraFocusPoint(long instance, float x, float y);

    native int nativeSetCameraZoom(long instance, float zoom);

    native int nativeSetCurrentCameraID(long instance, String cameraID);

    native int nativeSetCurrentCameraName(long instance, String cameraName);

    native int nativeSetExternalAudioRender(long instance, boolean enable, int sampleRate, int channels);

    native int nativeSetExternalAudioSource(long instance, boolean enable, int sampleRate, int channels);

    native int nativeSetExternalVideoSource(long instance, boolean enable, int track);

    native int nativeSetGroupName(long instance, String groupId, String name);

    native int nativeSetLocalViewConfig(long instance, int track, Object view, int textureId, int textureWidth, int textureHeight, long sharedContext, boolean enableBeauty, int renderMode, int mirrorMode, int rotationMode, int backgroundColor, boolean toBeRemoved);

    native int nativeSetParameters(long handle, String params);

    native int nativeSetPlayoutSignalVolume(long instance, int volume);

    native int nativeSetRecordingSignalVolume(long instance, int volume);

    native int nativeSetRemoteDefaultVideoStreamType(long instance, int streamType);

    native int nativeSetRemoteVideoStreamType(long instance, String uid, int streamType);

    native int nativeSetRemoteViewConfig(long instance, String uid, int track, Object view, int textureId, int textureWidth, int textureHeight, long sharedContext, boolean enableBeauty, int renderMode, int mirrorMode, int rotationMode, int backgroundColor, boolean toBeRemoved);

    native int nativeSetScreenShareEncoderConfiguration(long instance, int width, int height, int fps);

    native int nativeSetVideoDenoise(long nativePtr, int mode);

    native int nativeSetVideoEncoderConfiguration(long instance, int width, int height, int fps, int orientation_mode, int rotation, int mirror_mode);

    native int nativeSetVideoEnhance(long nativePtr, int mode);

    native int nativeSnapshotVideo(long instance, String uid, int videoTrack, String path);

    native int nativeStartAudioCapture(long instance);

    native int nativeStartAudioMixing(long instance, int id, boolean enablePublish, boolean enablePlayout, int publishVolume, int playoutVolume, int cycles, long startPosMs);

    native int nativeStartAudioPlayer(long instance);

    native int nativeStartPlayoutDeviceTest(long instance, String wavPath);

    native int nativeStartPreview(long instance);

    native int nativeStartRecordingDeviceTest(long instance);

    native int nativeStartScreenShare(long instance, Intent intent, int screenShareMode);

    native int nativeStopAudioCapture(long instance);

    native int nativeStopAudioMixing(long instance, int id);

    native int nativeStopAudioPlayer(long instance);

    native int nativeStopPlayoutDeviceTest(long instance);

    native int nativeStopPreview(long instance);

    native int nativeStopRecordingDeviceTest(long instance);

    native int nativeStopScreenShare(long instance);

    native int nativeSubscribeAllRemoteAudioStreams(long instance, boolean sub);

    native int nativeSubscribeAllRemoteVideoStreams(long instance, boolean sub);

    native int nativeSubscribeRemoteVideoStream(long instance, String uid, int track, boolean sub);

    native int nativeSwitchCamera(long instance);

    native int nativeSwitchSubscriptionToGroup(long instance, String groupId);

    native int nativeUnRegisterVideoCallback(long instance);

    native int nativeUpdateViewConfig(long instance, String uid, int track, Object view, int renderMode, int mirrorMode, int rotationMode, int backgroundColor);

    public static int setLogPath(String path) {
        if (!FileUtil.createFilePath(null, path)) {
            return -1;
        }
        nativeSetLogDirPath(path);
        return 0;
    }

    public RtcEngineImpl(Context context, String extra) {
        ContextUtils.initialize(context.getApplicationContext());
        try {
            JSONObject extraJO = new JSONObject(extra);
            DeviceMonitor.setNeedCollectWifiRssiData(extraJO.getBoolean("NO_WIFI_RSSI_DATA"));
            DeviceMonitor.setIsInCall(false);
        } catch (JSONException e) {
            Log.e(TAG, e.getMessage());
        }
        Logging.enableLogToDebugOutput(Logging.Severity.LS_INFO);
        this.mRtcEngineEventListener = new RtcEngineEventListener();
        this.mExternVideoSampleObserver = new RtcEngineVideoCallbackObserver();
        this.mExternalAudioFrameObserver = new RtcEngineAudioCallbackObserver();
        long jNativeCreate = nativeCreate(extra, this.mRtcEngineEventListener);
        this.mNativePtr = jNativeCreate;
        this.mWhiteboardManagerImpl = new RtcEngineWhiteboardManagerImpl(context, jNativeCreate);
        this.mRtmClientImpl = new RtmClientImpl(this.mNativePtr);
    }

    boolean checkNativeInvalid() {
        if (this.mNativePtr == 0) {
            Log.w(TAG, "native ptr null");
            return true;
        }
        return false;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void destroy() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                return;
            }
            if (this.mExternalAudioFrameObserver != null) {
                this.mExternalAudioFrameObserver.setAudioFrameObserver(null);
            }
            nativeDestroy(this.mNativePtr);
            this.mNativePtr = 0L;
            DeviceMonitor.setIsInCall(false);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int joinChannel(DingRtcAuthInfo authInfo, String userName) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "joinChannel failed! sdk not initialized");
            return 16974340;
        }
        DeviceMonitor.setIsInCall(true);
        return nativeJoinChannel(this.mNativePtr, authInfo, userName);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int leaveChannel() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "leaveChannel failed! sdk not initialized");
            return 16974340;
        }
        DeviceMonitor.setIsInCall(false);
        return nativeLeaveChannel(this.mNativePtr, 0L);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isInCall() {
        if (checkNativeInvalid()) {
            return false;
        }
        return nativeIsInCall(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraCapturerConfiguration(DingRtcEngine.DingEngineCameraCapturerConfiguration cameraCapturerConfiguration) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraCapturerConfiguration failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraCapturerConfiguration(this.mNativePtr, cameraCapturerConfiguration.preference.getValue(), cameraCapturerConfiguration.cameraDirection.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public SurfaceView createRenderSurfaceView(Context context) {
        return new RTCSurfaceView(context.getApplicationContext());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public TextureView createRenderTextureView(Context context) {
        return new RTCTextureView(context.getApplicationContext());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setLocalViewConfig(DingRtcEngine.DingRtcVideoCanvas canvas, DingRtcEngine.DingRtcVideoTrack track) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setLocalViewConfig failed! sdk not initialized");
            return 16974340;
        }
        if (track != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera && track != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen) {
            Logging.e(TAG, "setLocalViewConfig failed! not support track: " + track);
            return 16974340;
        }
        if (canvas != null) {
            int renderMode = (canvas.renderMode != null ? canvas.renderMode : DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto).getValue();
            int mirrorMode = (canvas.mirrorMode != null ? canvas.mirrorMode : DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeOnlyFront).getValue();
            int rotationMode = (canvas.rotationMode != null ? canvas.rotationMode : DingRtcEngine.DingRtcRotationMode.DingRtcRotationMode_0).getValue();
            int ret = nativeSetLocalViewConfig(this.mNativePtr, track.getValue(), canvas.view, canvas.textureId, canvas.textureWidth, canvas.textureHeight, canvas.sharedContext, canvas.enableBeauty, renderMode, mirrorMode, rotationMode, canvas.backgroundColor, canvas.toBeRemoved);
            return ret;
        }
        int ret2 = nativeSetLocalViewConfig(this.mNativePtr, track.getValue(), null, 0, 0, 0, 0L, false, DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto.getValue(), DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeOnlyFront.getValue(), DingRtcEngine.DingRtcRotationMode.DingRtcRotationMode_0.getValue(), 0, true);
        return ret2;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startPreview() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "startPreview failed! sdk not initialized");
            return 16974340;
        }
        return nativeStartPreview(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int stopPreview() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "stopPreview failed! sdk not initialized");
            return 16974340;
        }
        return nativeStopPreview(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableLocalVideo(boolean enabled) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "enableLocalVideo failed! sdk not initialized");
            return 16974340;
        }
        return nativeEnableLocalVideo(this.mNativePtr, enabled);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int muteLocalCamera(boolean mute, DingRtcEngine.DingRtcVideoTrack track) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "muteLocalCamera failed! sdk not initialized");
            return 16974340;
        }
        return nativeMuteLocalCamera(this.mNativePtr, mute, track.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int snapshotVideo(String uid, DingRtcEngine.DingRtcVideoTrack track, String path) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "snapshotVideo failed! sdk not initialized");
            return 16974340;
        }
        if (track == null || track == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackBoth || track == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo) {
            Logging.e(TAG, "snapshotVideo failed! track invalid");
            return 16974083;
        }
        if (!TextUtils.isEmpty(path)) {
            return nativeSnapshotVideo(this.mNativePtr, uid == null ? "" : uid, track.getValue(), path);
        }
        Logging.e(TAG, "snapshotVideo failed! path invalid");
        return 16974083;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int publishLocalVideoStream(boolean enabled) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "publishLocalVideoStream failed! sdk not initialized");
            return 16974340;
        }
        return nativePublishLocalVideoStream(this.mNativePtr, enabled);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int publishLocalAudioStream(boolean enabled) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "publishLocalAudioStream failed! sdk not initialized");
            return 16974340;
        }
        return nativePublishLocalAudioStream(this.mNativePtr, enabled);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int muteLocalMic(boolean mute, DingRtcEngine.DingRtcMuteLocalAudioMode mode) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "muteLocalMic failed! sdk not initialized");
            return 16974340;
        }
        return nativeMuteLocalMic(this.mNativePtr, mute, mode.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int muteLocalAudio(boolean mute) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "muteLocalAudio failed! sdk not initialized");
            return 16974340;
        }
        return nativeMuteLocalAudio(this.mNativePtr, mute);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int muteRemoteAudio(String uid, boolean mute) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "muteRemoteAudio failed! sdk not initialized");
            return 16974340;
        }
        return nativeMuteRemoteAudio(this.mNativePtr, uid, mute);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void setVideoEncoderConfiguration(DingRtcEngine.DingRtcVideoEncoderConfiguration config) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setVideoEncoderConfiguration failed! sdk not initialized");
        } else {
            nativeSetVideoEncoderConfiguration(this.mNativePtr, config.dimensions.width, config.dimensions.height, config.frameRate, config.orientationMode.getValue(), config.rotation.getValue(), config.mirrorMode.getValue());
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void setScreenShareEncoderConfiguration(DingRtcEngine.DingRtcScreenShareEncoderConfiguration config) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setScreenShareEncoderConfiguration failed! sdk not initialized");
        } else {
            nativeSetScreenShareEncoderConfiguration(this.mNativePtr, config.dimensions.width, config.dimensions.height, config.frameRate);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setRemoteViewConfig(DingRtcEngine.DingRtcVideoCanvas canvas, String uid, DingRtcEngine.DingRtcVideoTrack track) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setRemoteViewConfig failed! sdk not initialized");
            return 16974340;
        }
        if (TextUtils.isEmpty(uid)) {
            Logging.e(TAG, "setRemoteViewConfig failed! uid is null");
            return 16974340;
        }
        if (track != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera && track != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen) {
            Logging.e(TAG, "setRemoteViewConfig failed! not support track: " + track);
            return 16974340;
        }
        if (canvas != null) {
            int renderMode = (canvas.renderMode != null ? canvas.renderMode : DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto).getValue();
            int mirrorMode = (canvas.mirrorMode != null ? canvas.mirrorMode : DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeOnlyFront).getValue();
            int rotationMode = (canvas.rotationMode != null ? canvas.rotationMode : DingRtcEngine.DingRtcRotationMode.DingRtcRotationMode_0).getValue();
            int ret = nativeSetRemoteViewConfig(this.mNativePtr, uid, track.getValue(), canvas.view, canvas.textureId, canvas.textureWidth, canvas.textureHeight, canvas.sharedContext, canvas.enableBeauty, renderMode, mirrorMode, rotationMode, canvas.backgroundColor, canvas.toBeRemoved);
            return ret;
        }
        int ret2 = nativeSetRemoteViewConfig(this.mNativePtr, uid, track.getValue(), null, 0, 0, 0, 0L, false, DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto.getValue(), DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeOnlyFront.getValue(), DingRtcEngine.DingRtcRotationMode.DingRtcRotationMode_0.getValue(), 0, true);
        return ret2;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int updateViewConfig(DingRtcEngine.DingRtcVideoCanvas canvas, String uid, DingRtcEngine.DingRtcVideoTrack track) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "updateViewConfig failed! sdk not initialized");
            return 16974340;
        }
        if (track != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera && track != DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen) {
            Logging.e(TAG, "updateViewConfig failed! not support track: " + track);
            return 16974340;
        }
        if (canvas == null) {
            return -1;
        }
        int renderMode = (canvas.renderMode != null ? canvas.renderMode : DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto).getValue();
        int mirrorMode = (canvas.mirrorMode != null ? canvas.mirrorMode : DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeOnlyFront).getValue();
        int rotationMode = (canvas.rotationMode != null ? canvas.rotationMode : DingRtcEngine.DingRtcRotationMode.DingRtcRotationMode_0).getValue();
        int ret = nativeUpdateViewConfig(this.mNativePtr, uid, track.getValue(), canvas.view, renderMode, mirrorMode, rotationMode, canvas.backgroundColor);
        return ret;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isLocalVideoStreamPublished() {
        if (checkNativeInvalid()) {
            return false;
        }
        return nativeIsLocalVideoStreamPublished(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isScreenSharePublished() {
        if (checkNativeInvalid()) {
            return false;
        }
        return nativeIsScreenSharePublished(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isLocalAudioStreamPublished() {
        if (checkNativeInvalid()) {
            return false;
        }
        return nativeIsLocalAudioStreamPublished(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setRemoteVideoStreamType(String uid, DingRtcEngine.DingRtcVideoStreamType streamType) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setRemoteVideoStreamType failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetRemoteVideoStreamType(this.mNativePtr, uid, streamType.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setRemoteDefaultVideoStreamType(DingRtcEngine.DingRtcVideoStreamType streamType) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setRemoteDefaultVideoStreamType failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetRemoteDefaultVideoStreamType(this.mNativePtr, streamType.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int subscribeAllRemoteAudioStreams(boolean sub) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "subscribeAllRemoteAudioStreams failed! sdk not initialized");
            return 16974340;
        }
        return nativeSubscribeAllRemoteAudioStreams(this.mNativePtr, sub);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int subscribeAllRemoteVideoStreams(boolean sub) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "subscribeAllRemoteVideoStreams failed! sdk not initialized");
            return 16974340;
        }
        return nativeSubscribeAllRemoteVideoStreams(this.mNativePtr, sub);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int subscribeRemoteVideoStream(String uid, DingRtcEngine.DingRtcVideoTrack track, boolean sub) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "subscribeRemoteVideoStream failed! sdk not initialized");
            return 16974340;
        }
        return nativeSubscribeRemoteVideoStream(this.mNativePtr, uid, track.getValue(), sub);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public String[] getOnlineRemoteUsers() {
        if (checkNativeInvalid()) {
            return null;
        }
        return nativeGetOnlineRemoteUsers(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public DingRtcRemoteUserInfo getUserInfo(String uid) {
        if (checkNativeInvalid()) {
            return null;
        }
        return nativeGetUserInfo(this.mNativePtr, uid);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isUserOnline(String uid) {
        if (checkNativeInvalid()) {
            return false;
        }
        return nativeIsUserOnline(this.mNativePtr, uid);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableSpeakerphone(boolean enable) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "enableSpeakerphone failed! sdk not initialized");
            return 16974340;
        }
        return nativeEnableSpeakerphone(this.mNativePtr, enable);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isSpeakerphoneEnabled() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "isSpeakerphoneEnabled failed! sdk not initialized");
            return false;
        }
        return nativeIsSpeakerphoneEnabled(this.mNativePtr);
    }

    private DingRtcEngine.DingRtcAudioRouteType convertFromAudioRouteType(AudioRouteType type) {
        int audioRouteType = DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Default.getValue();
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[type.ordinal()];
        if (i == 1) {
            audioRouteType = DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Default.getValue();
        } else if (i == 2) {
            audioRouteType = DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Speakerphone.getValue();
        } else if (i == 3) {
            audioRouteType = DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Earpiece.getValue();
        } else if (i == 4) {
            audioRouteType = DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Headset.getValue();
        } else if (i == 5) {
            audioRouteType = DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_BlueTooth.getValue();
        }
        return DingRtcEngine.DingRtcAudioRouteType.fromValue(audioRouteType);
    }

    /* JADX INFO: renamed from: com.ding.rtc.RtcEngineImpl$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType;
        static final /* synthetic */ int[] $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType;

        static {
            int[] iArr = new int[DingRtcEngine.DingRtcAudioRouteType.values().length];
            $SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType = iArr;
            try {
                iArr[DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Default.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType[DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Speakerphone.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType[DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Earpiece.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType[DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_Headset.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType[DingRtcEngine.DingRtcAudioRouteType.DingRtcAudioRouteType_BlueTooth.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            int[] iArr2 = new int[AudioRouteType.values().length];
            $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType = iArr2;
            try {
                iArr2[AudioRouteType.None.ordinal()] = 1;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.Speakerphone.ordinal()] = 2;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.Earpiece.ordinal()] = 3;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.WiredHeadset.ordinal()] = 4;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.Bluetooth.ordinal()] = 5;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.A2dp.ordinal()] = 6;
            } catch (NoSuchFieldError e11) {
            }
        }
    }

    private AudioRouteType convertToAudioRouteType(DingRtcEngine.DingRtcAudioRouteType type) {
        AudioRouteType audioRouteType = AudioRouteType.None;
        int i = AnonymousClass1.$SwitchMap$com$ding$rtc$DingRtcEngine$DingRtcAudioRouteType[type.ordinal()];
        if (i == 1) {
            AudioRouteType audioRouteType2 = AudioRouteType.None;
            return audioRouteType2;
        }
        if (i == 2) {
            AudioRouteType audioRouteType3 = AudioRouteType.Speakerphone;
            return audioRouteType3;
        }
        if (i == 3) {
            AudioRouteType audioRouteType4 = AudioRouteType.Earpiece;
            return audioRouteType4;
        }
        if (i == 4) {
            AudioRouteType audioRouteType5 = AudioRouteType.WiredHeadset;
            return audioRouteType5;
        }
        if (i == 5) {
            AudioRouteType audioRouteType6 = AudioRouteType.Bluetooth;
            return audioRouteType6;
        }
        AudioRouteType audioRouteType7 = AudioRouteType.None;
        return audioRouteType7;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public List<DingRtcEngine.DingRtcAudioDeviceInfo> getAudioDevices() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getAudioDevices failed! sdk not initialized");
            return null;
        }
        List<DingRtcEngine.DingRtcAudioDeviceInfo> audioDeviceInfos = new ArrayList<>();
        List<AudioDeviceSwitcher.AudioDeviceInfo> deviceInfos = AudioDeviceSwitcher.getInstance().getAllAudioDevices();
        for (AudioDeviceSwitcher.AudioDeviceInfo deviceInfo : deviceInfos) {
            audioDeviceInfos.add(new DingRtcEngine.DingRtcAudioDeviceInfo(deviceInfo.getName(), convertFromAudioRouteType(deviceInfo.getType()), deviceInfo.isUsed()));
        }
        return audioDeviceInfos;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean setAudioRouteType(DingRtcEngine.DingRtcAudioRouteType route) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setAudioRouteType failed! sdk not initialized");
            return false;
        }
        return AudioDeviceSwitcher.getInstance().activate(convertToAudioRouteType(route));
    }

    @Override // com.ding.rtc.DingRtcEngine
    public List<DingRtcEngine.DingRtcVideoDeviceInfo> getCameraList() {
        CameraEnumerator enumerator = new Camera1Enumerator();
        String[] cameraList = enumerator.getDeviceNames();
        String str = TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("camera : 0 ");
        sb.append(cameraList[0]);
        Logging.i(str, sb.toString());
        List<DingRtcEngine.DingRtcVideoDeviceInfo> deviceInfos = new ArrayList<>();
        for (String device : cameraList) {
            boolean frontFacing = enumerator.isFrontFacing(device);
            Logging.i(TAG, "camera :" + device + "," + cameraList.length);
            deviceInfos.add(new DingRtcEngine.DingRtcVideoDeviceInfo(device, device, frontFacing ? DingRtcEngine.DingRtcCameraDirection.CAMERA_FRONT : DingRtcEngine.DingRtcCameraDirection.CAMERA_REAR));
        }
        return deviceInfos;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public String getCurrentCameraName() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getCurrentCameraName failed! sdk not initialized");
            return "";
        }
        return nativeGetCurrentCameraName(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public String getCurrentCameraID() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getCurrentCameraID failed! sdk not initialized");
            return "";
        }
        return nativeGetCurrentCameraID(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCurrentCameraName(String cameraName) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCurrentCameraName failed! sdk not initialized");
            return -1;
        }
        return nativeSetCurrentCameraName(this.mNativePtr, cameraName);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCurrentCameraID(String cameraID) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCurrentCameraName failed! sdk not initialized");
            return -1;
        }
        return nativeSetCurrentCameraID(this.mNativePtr, cameraID);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isCameraOn() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "isCameraOn failed! sdk not initialized");
            return false;
        }
        return nativeIsCameraOn(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public DingRtcEngine.DingRtcCameraDirection getCurrentCameraDirection() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getCurrentCameraDirection failed! sdk not initialized");
            return DingRtcEngine.DingRtcCameraDirection.CAMERA_INVALID;
        }
        return DingRtcEngine.DingRtcCameraDirection.getByValue(nativeGetCurrentCameraDirection(this.mNativePtr));
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int switchCamera() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "switchCamera failed! sdk not initialized");
            return 16974340;
        }
        return nativeSwitchCamera(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraZoom(float zoom) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraZoom failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraZoom(this.mNativePtr, zoom);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraFlash(boolean flash) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraFlash failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraFlash(this.mNativePtr, flash);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isCameraFocusPointSupported() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "isCameraFocusPointSupported failed! sdk not initialized");
            return false;
        }
        return nativeIsCameraFocusPointSupported(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraFocusPoint(float x, float y) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraFocusPoint failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraFocusPoint(this.mNativePtr, x, y);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isCameraExposurePointSupported() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "isCameraExposurePointSupported failed! sdk not initialized");
            return false;
        }
        return nativeIsCameraExposurePointSupported(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraExposurePoint(float x, float y) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraExposurePoint failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraExposurePoint(this.mNativePtr, x, y);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public boolean isCameraAutoFocusFaceModeSupported() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "isCameraAutoFocusFaceModeSupported failed! sdk not initialized");
            return false;
        }
        return nativeIsCameraAutoFocusFaceModeSupported(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraAutoFocusFaceModeEnabled(boolean enable) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraAutoFocusFaceModeEnabled failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraAutoFocusFaceModeEnabled(this.mNativePtr, enable);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setCameraExposureCompensation(float value) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setCameraExposureCompensation failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetCameraExposureCompensation(this.mNativePtr, value);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public float getCameraMinExposureCompensation() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getCameraMinExposureCompensation failed! sdk not initialized");
            return 0.0f;
        }
        return nativeGetCameraMinExposureCompensation(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public float getCameraMaxExposureCompensation() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getCameraMaxExposureCompensation failed! sdk not initialized");
            return 0.0f;
        }
        return nativeGetCameraMaxExposureCompensation(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setAudioProfile(DingRtcEngine.DingRtcAudioProfile profile, DingRtcEngine.DingRtcAudioScenario scenario) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setAudioProfile failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetAudioProfile(this.mNativePtr, profile.getValue(), scenario.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableAudioVolumeIndication(int interval, int smooth, int reportVad) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "enableAudioVolumeIndication failed! sdk not initialized");
            return 16974340;
        }
        return nativeEnableAudioVolumeIndication(this.mNativePtr, interval, smooth, reportVad);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void setRtcEngineEventListener(DingRtcEngineEventListener listener) {
        this.mRtcEngineEventListener.setRtcEngineEventListener(listener);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void registerAudioFrameObserver(DingRtcEngine.DingRtcAudioFrameObserver observer) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "registerAudioFrameObserver failed! sdk not initialized");
                return;
            }
            this.mExternalAudioFrameObserver.setAudioFrameObserver(observer);
            if (observer != null) {
                nativeRegisterAudioFrameObserver(this.mNativePtr, this.mExternalAudioFrameObserver);
            } else {
                nativeRegisterAudioFrameObserver(this.mNativePtr, null);
            }
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableAudioFrameObserver(boolean enable, int position) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "enableAudioFrameObserver2 failed! sdk not initialized");
                return -1;
            }
            return nativeEnableAudioFrameObserver2(this.mNativePtr, enable, position);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableAudioFrameObserver(boolean enabled, int position, DingRtcEngine.DingRtcAudioFrameObserverConfig config) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "enableAudioFrameObserver3 failed! sdk not initialized");
                return -1;
            }
            if (config == null || config.sampleRate == null || config.channels == null) {
                Logging.e(TAG, " - config param invalid, use default params");
                config = new DingRtcEngine.DingRtcAudioFrameObserverConfig();
            }
            int sampleRate = config.sampleRate.getId();
            int channels = config.channels.getValue();
            boolean readOnly = config.permission == DingRtcEngine.DingRtcAudioFramePermission.DingRtcAudioFramePermissionReadOnly;
            return nativeEnableAudioFrameObserver3(this.mNativePtr, enabled, position, sampleRate, channels, readOnly);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startRecordingDeviceTest() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "startRecordingDeviceTest failed! sdk not initialized");
                return -1;
            }
            return nativeStartRecordingDeviceTest(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int stopRecordingDeviceTest() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "stopRecordingDeviceTest failed! sdk not initialized");
                return -1;
            }
            return nativeStopRecordingDeviceTest(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startPlayoutDeviceTest(String wavPath) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "startPlayoutDeviceTest failed! sdk not initialized");
                return -1;
            }
            return nativeStartPlayoutDeviceTest(this.mNativePtr, wavPath);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int stopPlayoutDeviceTest() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "stopPlayoutDeviceTest failed! sdk not initialized");
                return -1;
            }
            return nativeStopPlayoutDeviceTest(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startAudioCapture() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "startAudioCapture failed! sdk not initialized");
                return -1;
            }
            return nativeStartAudioCapture(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int stopAudioCapture() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "stopAudioCapture failed! sdk not initialized");
                return -1;
            }
            return nativeStopAudioCapture(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startAudioPlayer() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "startAudioPlayer failed! sdk not initialized");
                return -1;
            }
            return nativeStartAudioPlayer(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int stopAudioPlayer() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "stopAudioPlayer failed! sdk not initialized");
                return -1;
            }
            return nativeStopAudioPlayer(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setPlayoutVolume(int volume) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setPlayoutVolume failed! sdk not initialized");
                return -1;
            }
            return nativeSetPlayoutSignalVolume(this.mNativePtr, volume);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int getPlayoutVolume() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "getPlayoutVolume failed! sdk not initialized");
                return -1;
            }
            return nativeGetPlayoutSignalVolume(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setRecordingVolume(int volume) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setRecordingVolume failed! sdk not initialized");
                return -1;
            }
            return nativeSetRecordingSignalVolume(this.mNativePtr, volume);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int getRecordingVolume() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "getRecordingVolume failed! sdk not initialized");
                return -1;
            }
            return nativeGetRecordingSignalVolume(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setPlayoutSignalVolume(int volume) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setPlayoutSignalVolume failed! sdk not initialized");
                return -1;
            }
            return nativeSetPlayoutSignalVolume(this.mNativePtr, volume);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int getPlayoutSignalVolume() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "getPlayoutSignalVolume failed! sdk not initialized");
                return -1;
            }
            return nativeGetPlayoutSignalVolume(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setRecordingSignalVolume(int volume) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setRecordingSignalVolume failed! sdk not initialized");
                return -1;
            }
            return nativeSetRecordingSignalVolume(this.mNativePtr, volume);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int getRecordingSignalVolume() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "getRecordingSignalVolume failed! sdk not initialized");
                return -1;
            }
            return nativeGetRecordingSignalVolume(this.mNativePtr);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int muteRecordingSignal(boolean mute) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "muteRecordingSignal failed! sdk not initialized");
                return -1;
            }
            return nativeMuteRecordingSignal(this.mNativePtr, mute);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void registerVideoSampleObserver(DingRtcEngine.DingRtcVideoObserver observer) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "registerVideoSampleObserver failed! sdk not initialized");
                return;
            }
            this.mExternVideoSampleObserver.setVideoSampleObserver(observer);
            if (observer == null) {
                nativeUnRegisterVideoCallback(this.mNativePtr);
            } else {
                nativeRegisterVideoCallback(this.mNativePtr, this.mExternVideoSampleObserver);
            }
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public void unRegisterVideoSampleObserver() {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "unRegisterVideoSampleObserver failed! sdk not initialized");
            } else {
                nativeUnRegisterVideoCallback(this.mNativePtr);
                this.mExternVideoSampleObserver.setVideoSampleObserver(null);
            }
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setParameters(String params) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setParameters failed! sdk not initialized");
                return -1;
            }
            return nativeSetParameters(this.mNativePtr, params);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableVideoSampleObserver(boolean enable, int position) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "enableVideoSampleObserver failed! sdk not initialized");
                return -1;
            }
            return nativeEnableVideoSampleObserver(this.mNativePtr, enable, position);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setExternalVideoSource(boolean enable, boolean useTexture, DingRtcEngine.DingRtcVideoTrack streamType, DingRtcEngine.DingRtcRenderMode renderMode) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setExternalVideoSource failed! sdk not initialized");
                return 16974340;
            }
            return nativeSetExternalVideoSource(this.mNativePtr, enable, streamType.getValue());
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int pushExternalVideoFrame(DingRtcEngine.DingRtcRawDataFrame rawDataFrame, DingRtcEngine.DingRtcVideoTrack streamType) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "pushExternalVideoFrame failed! sdk not initialized");
                return 16974340;
            }
            return nativePushExternalVideoFrame(this.mNativePtr, convertVideoFrame(rawDataFrame), streamType.getValue());
        }
    }

    private RtcEngineRawDataFrame convertVideoFrame(DingRtcEngine.DingRtcRawDataFrame rawDataFrame) {
        RtcEngineRawDataFrame videoFrame = new RtcEngineRawDataFrame();
        videoFrame.data = rawDataFrame.frame;
        videoFrame.format = rawDataFrame.format.getValue();
        videoFrame.width = rawDataFrame.width;
        videoFrame.height = rawDataFrame.height;
        videoFrame.strideY = rawDataFrame.lineSize[0];
        videoFrame.strideU = rawDataFrame.lineSize[1];
        videoFrame.strideV = rawDataFrame.lineSize[2];
        videoFrame.rotate = rawDataFrame.rotation;
        videoFrame.timestamp = rawDataFrame.timestamp;
        return videoFrame;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setExternalAudioSource(boolean enable, int sampleRate, int channels) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setExternalAudioSource failed! sdk not initialized");
                return 16974340;
            }
            return nativeSetExternalAudioSource(this.mNativePtr, enable, sampleRate, channels);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int pushExternalAudioFrame(DingRtcEngine.DingRtcAudioFrame frame) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "pushExternalAudioFrame failed! sdk not initialized");
                return 16974340;
            }
            if (frame == null) {
                return 16974083;
            }
            RtcEngineAudioRawFrame innerFrame = new RtcEngineAudioRawFrame(frame);
            return nativePushExternalAudioFrame(this.mNativePtr, innerFrame);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setExternalAudioRender(boolean enable, int sampleRate, int channels) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "setExternalAudioRender failed! sdk not initialized");
                return 16974340;
            }
            return nativeSetExternalAudioRender(this.mNativePtr, enable, sampleRate, channels);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int pushExternalAudioRenderFrame(DingRtcEngine.DingRtcAudioFrame frame) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "pushExternalAudioRenderFrame failed! sdk not initialized");
                return 16974340;
            }
            if (frame == null) {
                return 16974083;
            }
            RtcEngineAudioRawFrame innerFrame = new RtcEngineAudioRawFrame(frame);
            return nativePushExternalAudioRenderFrame(this.mNativePtr, innerFrame);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableCustomAudioCapture(boolean enable) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "enableCustomAudioCapture failed! sdk not initialized");
                return 16974340;
            }
            return nativeEnableCustomAudioCapture(this.mNativePtr, enable);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int sendCustomAudioCaptureFrame(DingRtcEngine.DingRtcAudioFrame frame) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "sendCustomAudioCaptureFrame failed! sdk not initialized");
                return 16974340;
            }
            if (frame == null) {
                return 16974083;
            }
            RtcEngineAudioRawFrame innerFrame = new RtcEngineAudioRawFrame(frame);
            return nativeSendCustomAudioCaptureFrame(this.mNativePtr, innerFrame);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableCustomAudioRender(boolean enable) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "enableCustomAudioRender failed! sdk not initialized");
                return 16974340;
            }
            return nativeEnableCustomAudioRender(this.mNativePtr, enable);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int getCustomAudioRenderFrame(DingRtcEngine.DingRtcAudioFrame frame) {
        synchronized (this.mEngineLock) {
            if (checkNativeInvalid()) {
                Logging.e(TAG, "getCustomAudioRenderFrame failed! sdk not initialized");
                return 16974340;
            }
            if (frame == null) {
                return 16974083;
            }
            RtcEngineAudioRawFrame innerFrame = new RtcEngineAudioRawFrame(frame);
            return nativeGetCustomAudioRenderFrame(this.mNativePtr, innerFrame);
        }
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableBeautyFace(boolean enable, DingRtcEngine.DingRtcBeautyFaceOptions options) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setBeautyEffect failed! sdk not initialized");
            return 16974340;
        }
        if (!enable && options == null) {
            options = new DingRtcEngine.DingRtcBeautyFaceOptions();
            options.resourcePath = "n/a";
            options.enableSkinBuffing = false;
            options.enableSkinWhitening = false;
        }
        return nativeEnableBeautyFace(this.mNativePtr, enable, options.resourcePath, options.enableSkinBuffing, options.skinBuffingFactor, options.skinSharpenFactor, options.enableSkinWhitening, options.skinWhitingFactor, options.enableFilter, options.filterPath);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int enableVirtualBackground(boolean enable, DingRtcEngine.DingRtcVirtualBackgroundOptions options) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setVirtualBackground failed! sdk not initialized");
            return 16974340;
        }
        if (enable) {
            if (options == null || options.mode == null) {
                return 16974083;
            }
            if (options.mode == DingRtcEngine.DingRtcEngineVirtualBackgroundMode.DingRtcEngineVirtualBackgroundReplace && TextUtils.isEmpty(options.bgFilePath)) {
                return 16974083;
            }
        } else if (options == null || options.mode == null) {
            options = new DingRtcEngine.DingRtcVirtualBackgroundOptions();
        }
        return nativeEnableVirtualBackground(this.mNativePtr, enable, options.mode.getValue(), options.bgFilePath);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public DingRtcEngine.DingRtcConnectionStatus getCurrentConnectionStatus() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "startScreenShare failed! sdk not initialized");
            return DingRtcEngine.DingRtcConnectionStatus.DingRtcConnectionStatusInit;
        }
        return DingRtcEngine.DingRtcConnectionStatus.getDingRtcConnectionStatus(nativeGetCurrentConnectionStatus(this.mNativePtr));
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startScreenShare() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "startScreenShare failed! sdk not initialized");
            return 16974340;
        }
        return nativeStartScreenShare(this.mNativePtr, null, DingRtcEngine.DingRtcScreenShareMode.DingRtcScreenShareAllMode.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startScreenShare(DingRtcEngine.DingRtcScreenShareMode screenShareMode) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "startScreenShare with intent failed! sdk not initialized");
            return 16974340;
        }
        return nativeStartScreenShare(this.mNativePtr, null, screenShareMode.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int startScreenShare(Intent intent, DingRtcEngine.DingRtcScreenShareMode screenShareMode) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "startScreenShare with intent failed! sdk not initialized");
            return 16974340;
        }
        return nativeStartScreenShare(this.mNativePtr, intent, screenShareMode.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int stopScreenShare() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "stopScreenShare failed! sdk not initialized");
            return 16974340;
        }
        return nativeStopScreenShare(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setVideoEnhance(DingRtcEngine.DingRtcEngineVideoEnhanceOptions options) {
        if (checkNativeInvalid() || options == null || options.mode == null) {
            return 16974340;
        }
        return nativeSetVideoEnhance(this.mNativePtr, options.mode.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setVideoDenoise(DingRtcEngine.DingRtcEngineVideoDenoiseOptions options) {
        if (checkNativeInvalid()) {
            return 16974340;
        }
        if (options == null || options.mode == null) {
            return 16974083;
        }
        return nativeSetVideoDenoise(this.mNativePtr, options.mode.getValue());
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setAudioDenoise(DingRtcEngine.DingRtcEngineAudioDenoiseOptions options) {
        if (checkNativeInvalid()) {
            return 16974340;
        }
        if (options == null || options.mode == null) {
            return 16974083;
        }
        return nativeSetAudioDenoise(this.mNativePtr, options.mode.getValue());
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int createAudioMixing(int id, String filePath) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "createAudioMixing failed! sdk not initialized");
            return 16974340;
        }
        return nativeCreateAudioMixing(this.mNativePtr, id, filePath);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int destroyAudioMixing(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "destroyAudioMixing failed! sdk not initialized");
            return 16974340;
        }
        return nativeDestroyAudioMixing(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int startAudioMixing(int id, DingRtcEngine.DingRtcAudioMixingConfig config) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "startAudioMixing failed! sdk not initialized");
            return 16974340;
        }
        return nativeStartAudioMixing(this.mNativePtr, id, config.enablePublish, config.enablePlayout, config.publishVolume, config.playoutVolume, config.cycles, config.startPosMs);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int stopAudioMixing(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "stopAudioMixing failed! sdk not initialized");
            return 16974340;
        }
        return nativeStopAudioMixing(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int pauseAudioMixing(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "pauseAudioMixing failed! sdk not initialized");
            return 16974340;
        }
        return nativePauseAudioMixing(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int resumeAudioMixing(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "resumeAudioMixing failed! sdk not initialized");
            return 16974340;
        }
        return nativeResumeAudioMixing(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public long getAudioMixingDuration(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getAudioMixingDuration failed! sdk not initialized");
            return 16974340L;
        }
        return nativeGetAudioMixingDuration(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public long getAudioMixingCurrentPosition(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getAudioMixingCurrentPosition failed! sdk not initialized");
            return 16974340L;
        }
        return nativeGetAudioMixingCurrentPosition(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int setAudioMixingPosition(int id, long position) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setAudioMixingPosition failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetAudioMixingPosition(this.mNativePtr, id, position);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int setAudioMixingVolume(int id, int volume) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setAudioMixingVolume failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetAudioMixingVolume(this.mNativePtr, id, volume);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int getAudioMixingVolume(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getAudioMixingVolume failed! sdk not initialized");
            return 16974340;
        }
        return nativeGetAudioMixingVolume(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int setAudioMixingPublishVolume(int id, int volume) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setAudioMixingPublishVolume failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetAudioMixingPublishVolume(this.mNativePtr, id, volume);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int getAudioMixingPublishVolume(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getAudioMixingPublishVolume failed! sdk not initialized");
            return 16974340;
        }
        return nativeGetAudioMixingPublishVolume(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int setAudioMixingPlayoutVolume(int id, int volume) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setAudioMixingPlayoutVolume failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetAudioMixingPlayoutVolume(this.mNativePtr, id, volume);
    }

    @Override // com.ding.rtc.IAudioMixingManager
    public int getAudioMixingPlayoutVolume(int id) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getAudioMixingPlayoutVolume failed! sdk not initialized");
            return 16974340;
        }
        return nativeGetAudioMixingPlayoutVolume(this.mNativePtr, id);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int joinGroup(String groupId, String usrData) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "joinGroup failed! sdk not initialized");
            return 16974340;
        }
        return nativeJoinGroup(this.mNativePtr, groupId, usrData);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int leaveGroup(String groupId) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "leaveGroup failed! sdk not initialized");
            return 16974340;
        }
        return nativeLeaveGroup(this.mNativePtr, groupId);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int dismissGroup(String groupId) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "dismissGroup failed! sdk not initialized");
            return 16974340;
        }
        return nativeDismissGroup(this.mNativePtr, groupId);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int mixAudioToGroup(boolean mix, String groupId) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "mixAudioToGroup failed! sdk not initialized");
            return 16974340;
        }
        return nativeMixAudioToGroup(this.mNativePtr, mix, groupId);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int switchSubscriptionToGroup(String groupId) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "switchSubscriptionToGroup failed! sdk not initialized");
            return 16974340;
        }
        return nativeSwitchSubscriptionToGroup(this.mNativePtr, groupId);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public String getCurrentSubscribedAudio() {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "getCurrentSubscribedAudio failed! sdk not initialized");
            return "";
        }
        return nativeGetCurrentSubscribedAudio(this.mNativePtr);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int setGroupName(String groupId, String name) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "setGroupName failed! sdk not initialized");
            return 16974340;
        }
        return nativeSetGroupName(this.mNativePtr, groupId, name);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public int sendMediaExtensionMsg(byte[] message, int repeatCount) {
        if (checkNativeInvalid()) {
            Logging.e(TAG, "sendMediaExtensionMsg failed! sdk not initialized");
            return -1;
        }
        return nativeSendMediaExtensionMsg(this.mNativePtr, message, repeatCount);
    }

    @Override // com.ding.rtc.DingRtcEngine
    public DingRtcEngineWhiteboardManager getWhiteBoardManager() {
        return this.mWhiteboardManagerImpl;
    }

    @Override // com.ding.rtc.DingRtcEngine
    public DingRtmClient getRtmClient() {
        return this.mRtmClientImpl;
    }
}
