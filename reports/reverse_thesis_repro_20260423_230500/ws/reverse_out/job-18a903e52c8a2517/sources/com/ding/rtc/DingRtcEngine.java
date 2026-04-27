package com.ding.rtc;

import android.content.Context;
import android.content.Intent;
import android.graphics.Matrix;
import android.os.Build;
import android.system.Os;
import android.util.Log;
import android.view.SurfaceView;
import android.view.TextureView;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.util.List;
import javax.microedition.khronos.egl.EGLContext;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.JavaScreenCapturer;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes.dex */
public abstract class DingRtcEngine implements IAudioMixingManager {
    public static final String HALL_ID = "@Hall@";
    private static final String TAG = "DingRtcEngine";
    public static final DingRtcVideoDimensions VD_120x120;
    public static final DingRtcVideoDimensions VD_1280x720;
    public static final DingRtcVideoDimensions VD_160x120;
    public static final DingRtcVideoDimensions VD_180x180;
    public static final DingRtcVideoDimensions VD_1920x1080;
    public static final DingRtcVideoDimensions VD_240x180;
    public static final DingRtcVideoDimensions VD_240x240;
    public static final DingRtcVideoDimensions VD_320x180;
    public static final DingRtcVideoDimensions VD_320x240;
    public static final DingRtcVideoDimensions VD_360x360;
    public static final DingRtcVideoDimensions VD_424x240;
    public static final DingRtcVideoDimensions VD_480x360;
    public static final DingRtcVideoDimensions VD_480x480;
    public static final DingRtcVideoDimensions VD_640x360;
    public static final DingRtcVideoDimensions VD_640x480;
    public static final DingRtcVideoDimensions VD_840x480;
    public static final DingRtcVideoDimensions VD_960x540;
    public static final DingRtcVideoDimensions VD_960x720;
    private static WeakReference<Context> mContext;

    public static class DingEngineCameraCapturerConfiguration {
        public DingRtcCaptureOutputPreference preference = DingRtcCaptureOutputPreference.DingRtc_CAPTURER_OUTPUT_PREFERENCE_AUTO;
        public DingRtcCameraDirection cameraDirection = DingRtcCameraDirection.CAMERA_FRONT;
    }

    public static class DingRtcAudioFrame {
        public int bytesPerSample;
        public ByteBuffer data;
        public int numChannels;
        public int numSamples;
        public int samplesPerSec;
    }

    public interface DingRtcAudioFrameObserver {
        void onCapturedAudioFrame(DingRtcAudioFrame frame);

        void onPlaybackAudioFrame(DingRtcAudioFrame frame);

        void onProcessCapturedAudioFrame(DingRtcAudioFrame frame);

        void onPublishAudioFrame(DingRtcAudioFrame frame);

        void onRemoteUserAudioFrame(String uid, DingRtcAudioFrame frame);
    }

    public static class DingRtcAudioFrameObserverConfig {
        public DingRtcAudioSampleRate sampleRate = DingRtcAudioSampleRate.DingRtcAudioSampleRate_48000;
        public DingRtcAudioNumChannel channels = DingRtcAudioNumChannel.DingRtcMonoAudio;
        public DingRtcAudioFramePermission permission = DingRtcAudioFramePermission.DingRtcAudioFramePermissionReadOnly;
        public int userDefinedInfo = DingRtcAudioFrameObserverUserDefinedInfoBitMask.DingRtcAudioFrameObserverUserDefinedInfoBitMaskMixExRender.getValue();
    }

    public static class DingRtcAudioObservePosition {
        public static final int RtcEngineAudioPositionCaptured = 1;
        public static final int RtcEngineAudioPositionPlayback = 8;
        public static final int RtcEngineAudioPositionProcessCaptured = 2;
        public static final int RtcEngineAudioPositionPub = 4;
        public static final int RtcEngineAudioPositionRemoteUser = 16;
    }

    public static class DingRtcBeautyFaceOptions {
        public boolean enableFilter;
        public String filterPath;
        public String resourcePath = null;
        public boolean enableSkinBuffing = false;
        public float skinBuffingFactor = 0.6f;
        public float skinSharpenFactor = 0.8f;
        public boolean enableSkinWhitening = false;
        public float skinWhitingFactor = 0.8f;
    }

    public static class DingRtcEngineAudioDenoiseOptions {
        public DingRtcEngineAudioDenoiseMode mode = DingRtcEngineAudioDenoiseMode.DingRtcEngineAudioDenoiseOff;
    }

    public static class DingRtcEngineVideoDenoiseOptions {
        public DingRtcEngineVideoDenoiseMode mode = DingRtcEngineVideoDenoiseMode.DingRtcEngineVideoDenoiseOff;
    }

    public static class DingRtcEngineVideoEnhanceOptions {
        public DingRtcEngineVideoEnhanceMode mode = DingRtcEngineVideoEnhanceMode.DingRtcEngineVideoEnhanceOff;
    }

    public static class DingRtcScreenShareEncoderConfiguration {
        public DingRtcVideoDimensions dimensions = new DingRtcVideoDimensions(0, 0);
        public int frameRate = DingRtcVideoEncoderFrameRate.DingRtcVideoEncoderFrameRate_FPS_5.getValue();
    }

    public static class DingRtcVideoEncoderConfiguration {
        public DingRtcVideoDimensions dimensions = new DingRtcVideoDimensions(640, 480);
        public int frameRate = DingRtcVideoEncoderFrameRate.DingRtcVideoEncoderFrameRate_FPS_15.getValue();
        public DingRtcVideoEncoderOrientationMode orientationMode = DingRtcVideoEncoderOrientationMode.DingRtcVideoEncoderOrientationModeAdaptive;
        public DingRtcRotationMode rotation = DingRtcRotationMode.DingRtcRotationMode_0;
        public DingRtcMirrorMode mirrorMode = DingRtcMirrorMode.DingRtcMirrorMode_Disable;
    }

    public static class DingRtcVideoObservePosition {
        public static final int DingRtcPositionPostCapture = 1;
        public static final int DingRtcPositionPreEncoder = 4;
        public static final int DingRtcPositionPreRender = 2;
    }

    public static class DingRtcVideoSample {
        public byte[] data;
        public EglBase.Context eglBaseContext;
        public Matrix transformMatrix;
        public VideoFrame.TextureBuffer.Type type;
        public long dataFrameY = 0;
        public long dataFrameU = 0;
        public long dataFrameV = 0;
        public DingRtcVideoFormat format = DingRtcVideoFormat.fromNativeIndex(1);
        public int width = 0;
        public int height = 0;
        public int strideY = 0;
        public int strideU = 0;
        public int strideV = 0;
        public int offsetY = 0;
        public int offsetU = 0;
        public int offsetV = 0;
        public int rotate = 0;
        public boolean mirror = false;
        public long extraData = 0;
        public int textureId = 0;
    }

    public enum DingRtcVideoSourceType {
        DingRtcSdkVideoSourceCameraType,
        DingRtcSdkVideoSourceScreenShareType
    }

    public static class DingRtcVirtualBackgroundOptions {
        public DingRtcEngineVirtualBackgroundMode mode = DingRtcEngineVirtualBackgroundMode.DingRtcEngineVirtualBackgroundBlur;
        public String bgFilePath = null;
    }

    public abstract SurfaceView createRenderSurfaceView(Context context);

    public abstract TextureView createRenderTextureView(Context context);

    public abstract void destroy();

    public abstract int dismissGroup(String groupId);

    public abstract int enableAudioFrameObserver(boolean enable, int position);

    public abstract int enableAudioFrameObserver(boolean enable, int position, DingRtcAudioFrameObserverConfig config);

    public abstract int enableAudioVolumeIndication(int interval, int smooth, int reportVad);

    public abstract int enableBeautyFace(boolean enable, DingRtcBeautyFaceOptions options);

    public abstract int enableCustomAudioCapture(boolean enable);

    public abstract int enableCustomAudioRender(boolean enable);

    public abstract int enableLocalVideo(boolean enabled);

    public abstract int enableSpeakerphone(boolean enable);

    public abstract int enableVideoSampleObserver(boolean enable, int position);

    public abstract int enableVirtualBackground(boolean enable, DingRtcVirtualBackgroundOptions options);

    public abstract List<DingRtcAudioDeviceInfo> getAudioDevices();

    public abstract List<DingRtcVideoDeviceInfo> getCameraList();

    public abstract float getCameraMaxExposureCompensation();

    public abstract float getCameraMinExposureCompensation();

    public abstract DingRtcCameraDirection getCurrentCameraDirection();

    public abstract String getCurrentCameraID();

    public abstract String getCurrentCameraName();

    public abstract DingRtcConnectionStatus getCurrentConnectionStatus();

    public abstract String getCurrentSubscribedAudio();

    public abstract int getCustomAudioRenderFrame(DingRtcAudioFrame frame);

    public abstract String[] getOnlineRemoteUsers();

    public abstract int getPlayoutSignalVolume();

    public abstract int getPlayoutVolume();

    public abstract int getRecordingSignalVolume();

    public abstract int getRecordingVolume();

    public abstract DingRtmClient getRtmClient();

    public abstract DingRtcRemoteUserInfo getUserInfo(String uid);

    public abstract DingRtcEngineWhiteboardManager getWhiteBoardManager();

    public abstract boolean isCameraAutoFocusFaceModeSupported();

    public abstract boolean isCameraExposurePointSupported();

    public abstract boolean isCameraFocusPointSupported();

    public abstract boolean isCameraOn();

    public abstract boolean isInCall();

    public abstract boolean isLocalAudioStreamPublished();

    public abstract boolean isLocalVideoStreamPublished();

    public abstract boolean isScreenSharePublished();

    public abstract boolean isSpeakerphoneEnabled();

    public abstract boolean isUserOnline(String uid);

    public abstract int joinChannel(DingRtcAuthInfo authInfo, String userName);

    public abstract int joinGroup(String groupId, String usrData);

    public abstract int leaveChannel();

    public abstract int leaveGroup(String groupId);

    public abstract int mixAudioToGroup(boolean mix, String groupId);

    public abstract int muteLocalAudio(boolean mute);

    public abstract int muteLocalCamera(boolean mute, DingRtcVideoTrack track);

    public abstract int muteLocalMic(boolean mute, DingRtcMuteLocalAudioMode mode);

    public abstract int muteRecordingSignal(boolean mute);

    public abstract int muteRemoteAudio(String uid, boolean mute);

    public abstract int publishLocalAudioStream(boolean enabled);

    public abstract int publishLocalVideoStream(boolean enabled);

    public abstract int pushExternalAudioFrame(DingRtcAudioFrame frame);

    public abstract int pushExternalAudioRenderFrame(DingRtcAudioFrame frame);

    public abstract int pushExternalVideoFrame(DingRtcRawDataFrame rawDataFrame, DingRtcVideoTrack streamType);

    public abstract void registerAudioFrameObserver(DingRtcAudioFrameObserver observer);

    public abstract void registerVideoSampleObserver(DingRtcVideoObserver observer);

    public abstract int sendCustomAudioCaptureFrame(DingRtcAudioFrame frame);

    public abstract int sendMediaExtensionMsg(byte[] message, int repeatCount);

    public abstract int setAudioDenoise(DingRtcEngineAudioDenoiseOptions options);

    public abstract int setAudioProfile(DingRtcAudioProfile profile, DingRtcAudioScenario scenario);

    public abstract boolean setAudioRouteType(DingRtcAudioRouteType route);

    public abstract int setCameraAutoFocusFaceModeEnabled(boolean enable);

    public abstract int setCameraCapturerConfiguration(DingEngineCameraCapturerConfiguration cameraCapturerConfiguration);

    public abstract int setCameraExposureCompensation(float value);

    public abstract int setCameraExposurePoint(float x, float y);

    public abstract int setCameraFlash(boolean flash);

    public abstract int setCameraFocusPoint(float x, float y);

    public abstract int setCameraZoom(float zoom);

    public abstract int setCurrentCameraID(String cameraID);

    public abstract int setCurrentCameraName(String cameraName);

    public abstract int setExternalAudioRender(boolean enable, int sampleRate, int channels);

    public abstract int setExternalAudioSource(boolean enable, int sampleRate, int channels);

    public abstract int setExternalVideoSource(boolean enable, boolean useTexture, DingRtcVideoTrack streamType, DingRtcRenderMode renderMode);

    public abstract int setGroupName(String groupId, String name);

    public abstract int setLocalViewConfig(DingRtcVideoCanvas viewConfig, DingRtcVideoTrack track);

    public abstract int setParameters(String params);

    public abstract int setPlayoutSignalVolume(int volume);

    public abstract int setPlayoutVolume(int volume);

    public abstract int setRecordingSignalVolume(int volume);

    public abstract int setRecordingVolume(int volume);

    public abstract int setRemoteDefaultVideoStreamType(DingRtcVideoStreamType streamType);

    public abstract int setRemoteVideoStreamType(String uid, DingRtcVideoStreamType streamType);

    public abstract int setRemoteViewConfig(DingRtcVideoCanvas canvas, String uid, DingRtcVideoTrack track);

    public abstract void setRtcEngineEventListener(DingRtcEngineEventListener listener);

    public abstract void setScreenShareEncoderConfiguration(DingRtcScreenShareEncoderConfiguration config);

    public abstract int setVideoDenoise(DingRtcEngineVideoDenoiseOptions options);

    public abstract void setVideoEncoderConfiguration(DingRtcVideoEncoderConfiguration config);

    public abstract int setVideoEnhance(DingRtcEngineVideoEnhanceOptions options);

    public abstract int snapshotVideo(String uid, DingRtcVideoTrack track, String path);

    public abstract int startAudioCapture();

    public abstract int startAudioPlayer();

    public abstract int startPlayoutDeviceTest(String wavPath);

    public abstract int startPreview();

    public abstract int startRecordingDeviceTest();

    public abstract int startScreenShare();

    public abstract int startScreenShare(Intent intent, DingRtcScreenShareMode screenShareMode);

    public abstract int startScreenShare(DingRtcScreenShareMode screenShareMode);

    public abstract int stopAudioCapture();

    public abstract int stopAudioPlayer();

    public abstract int stopPlayoutDeviceTest();

    public abstract int stopPreview();

    public abstract int stopRecordingDeviceTest();

    public abstract int stopScreenShare();

    public abstract int subscribeAllRemoteAudioStreams(boolean sub);

    public abstract int subscribeAllRemoteVideoStreams(boolean sub);

    public abstract int subscribeRemoteVideoStream(String uid, DingRtcVideoTrack track, boolean sub);

    public abstract int switchCamera();

    public abstract int switchSubscriptionToGroup(String groupId);

    public abstract void unRegisterVideoSampleObserver();

    public abstract int updateViewConfig(DingRtcVideoCanvas canvas, String uid, DingRtcVideoTrack track);

    static {
        try {
            if (Build.VERSION.SDK_INT <= 22) {
                Os.setenv("OPENSSL_armcap", "0", false);
            }
            System.loadLibrary("DingRtc");
        } catch (Throwable throwable) {
            Log.i(TAG, throwable.getMessage());
        }
        VD_120x120 = new DingRtcVideoDimensions(120, 120);
        VD_160x120 = new DingRtcVideoDimensions(160, 120);
        VD_180x180 = new DingRtcVideoDimensions(JavaScreenCapturer.DEGREE_180, JavaScreenCapturer.DEGREE_180);
        VD_240x180 = new DingRtcVideoDimensions(PsExtractor.VIDEO_STREAM_MASK, JavaScreenCapturer.DEGREE_180);
        VD_320x180 = new DingRtcVideoDimensions(320, JavaScreenCapturer.DEGREE_180);
        VD_240x240 = new DingRtcVideoDimensions(PsExtractor.VIDEO_STREAM_MASK, PsExtractor.VIDEO_STREAM_MASK);
        VD_320x240 = new DingRtcVideoDimensions(320, PsExtractor.VIDEO_STREAM_MASK);
        VD_424x240 = new DingRtcVideoDimensions(424, PsExtractor.VIDEO_STREAM_MASK);
        VD_360x360 = new DingRtcVideoDimensions(360, 360);
        VD_480x360 = new DingRtcVideoDimensions(480, 360);
        VD_640x360 = new DingRtcVideoDimensions(640, 360);
        VD_480x480 = new DingRtcVideoDimensions(480, 480);
        VD_640x480 = new DingRtcVideoDimensions(640, 480);
        VD_840x480 = new DingRtcVideoDimensions(840, 480);
        VD_960x540 = new DingRtcVideoDimensions(960, 540);
        VD_960x720 = new DingRtcVideoDimensions(960, 720);
        VD_1280x720 = new DingRtcVideoDimensions(1280, 720);
        VD_1920x1080 = new DingRtcVideoDimensions(1920, 1080);
    }

    public enum DingRtcEngineVideoEnhanceMode {
        DingRtcEngineVideoEnhanceOff(0),
        DingRtcEngineVideoEnhanceAuto(1);

        private final int value;

        DingRtcEngineVideoEnhanceMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcEngineVideoDenoiseMode {
        DingRtcEngineVideoDenoiseOff(0),
        DingRtcEngineVideoDenoiseAuto(1);

        private final int value;

        DingRtcEngineVideoDenoiseMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcEngineAudioDenoiseMode {
        DingRtcEngineAudioDenoiseOff(0),
        DingRtcEngineAudioDenoiseDsp(1),
        DingRtcEngineAudioDenoiseEnhance(2);

        private final int value;

        DingRtcEngineAudioDenoiseMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public static class DingRtcRawDataFrame {
        public int cropBottom;
        public int cropLeft;
        public int cropRight;
        public int cropTop;
        public EGLContext eglContext10;
        public android.opengl.EGLContext eglContext14;
        public DingRtcVideoFormat format;
        public byte[] frame;
        public int height;
        public int[] lineSize;
        public int rotation;
        public int textureId;
        public long timestamp;
        public float[] transformMatrix;
        public int videoFrameLength;
        public int width;

        public DingRtcRawDataFrame() {
            this.format = DingRtcVideoFormat.DingRtcVideoFormatI420;
            this.lineSize = new int[4];
        }

        public DingRtcRawDataFrame(byte[] frame, DingRtcVideoFormat format, int width, int height, int[] lineSize, int rotation, int frameLength) {
            this.format = DingRtcVideoFormat.DingRtcVideoFormatI420;
            this.lineSize = new int[4];
            this.frame = frame;
            this.format = format;
            this.width = width;
            this.height = height;
            this.lineSize = lineSize;
            this.rotation = rotation;
            this.videoFrameLength = frameLength;
        }

        public DingRtcRawDataFrame(int textureId, DingRtcVideoFormat format, int width, int height, float[] transformMatrix, int cropLeft, int cropTop, int cropRight, int cropBottom, android.opengl.EGLContext eglContext14) {
            this.format = DingRtcVideoFormat.DingRtcVideoFormatI420;
            this.lineSize = new int[4];
            this.textureId = textureId;
            this.format = format;
            this.width = width;
            this.height = height;
            this.cropLeft = cropLeft;
            this.cropTop = cropTop;
            this.cropRight = cropRight;
            this.cropBottom = cropBottom;
            this.eglContext14 = eglContext14;
            this.transformMatrix = transformMatrix;
        }

        public DingRtcRawDataFrame(int textureId, DingRtcVideoFormat format, int width, int height, float[] transformMatrix, int cropLeft, int cropTop, int cropRight, int cropBottom, EGLContext eglContext10) {
            this.format = DingRtcVideoFormat.DingRtcVideoFormatI420;
            this.lineSize = new int[4];
            this.textureId = textureId;
            this.format = format;
            this.width = width;
            this.height = height;
            this.cropLeft = cropLeft;
            this.cropTop = cropTop;
            this.cropRight = cropRight;
            this.cropBottom = cropBottom;
            this.eglContext10 = eglContext10;
            this.transformMatrix = transformMatrix;
        }
    }

    public static class DingRtcStats {
        public int appCpuRate;
        public int connectTimeMs;
        public long duration;
        public short lastmileDelay;
        public long rxAudioBytes;
        public short rxAudioKBitrate;
        public long rxBytes;
        public short rxKBitrate;
        public long rxLostPackets;
        public int rxPacketLossRate;
        public long rxPackets;
        public long rxVideoBytes;
        public short rxVideoKBitrate;
        public int systemCpuRate;
        public long txAudioBytes;
        public short txAudioKBitrate;
        public long txBytes;
        public short txKBitrate;
        public int txPacketLossRate;
        public long txVideoBytes;
        public short txVideoKBitrate;

        public String toString() {
            return "DingRtcStats{duration=" + this.duration + ", txBytes=" + this.txBytes + ", txAudioBytes=" + this.txAudioBytes + ", txVideoBytes=" + this.txVideoBytes + ", txKBitrate=" + ((int) this.txKBitrate) + ", txAudioKBitrate=" + ((int) this.txAudioKBitrate) + ", txVideoKBitrate=" + ((int) this.txVideoKBitrate) + ", txPacketLossRate=" + this.txPacketLossRate + ", rxBytes=" + this.rxBytes + ", rxPackets=" + this.rxPackets + ", rxAudioBytes=" + this.rxAudioBytes + ", rxVideoBytes=" + this.rxVideoBytes + ", rxKBitrate=" + ((int) this.rxKBitrate) + ", rxAudioKBitrate=" + ((int) this.rxAudioKBitrate) + ", rxVideoKBitrate=" + ((int) this.rxVideoKBitrate) + ", rxPacketLossRate=" + this.rxPacketLossRate + ", rxLostPackets=" + this.rxLostPackets + ", lastmileDelay=" + ((int) this.lastmileDelay) + ", connectTimeMs=" + this.connectTimeMs + ", systemCpuRate=" + this.systemCpuRate + ", appCpuRate=" + this.appCpuRate + '}';
        }
    }

    public static class DingRtcLocalVideoStats {
        public DingRtcVideoTrack track;
        public int targetEncodeBitrate = 0;
        public int actualEncodeBitrate = 0;
        public int sentBitrate = 0;
        public int sentFps = 0;
        public int encodeFps = 0;
        public int captureFps = 0;
        public int renderFps = 0;
        public int avgQpPerSec = 0;
        public int encoderFrameWidth = 0;
        public int encoderFrameHeight = 0;
        public int captureFrameWidth = 0;
        public int captureFrameHeight = 0;

        public String toString() {
            return "DingRtcLocalVideoStats{track=" + this.track + ", targetEncodeBitrate=" + this.targetEncodeBitrate + ", actualEncodeBitrate=" + this.actualEncodeBitrate + ", sentBitrate=" + this.sentBitrate + ", sentFps=" + this.sentFps + ", encodeFps=" + this.encodeFps + ", captureFps=" + this.captureFps + ", renderFps=" + this.renderFps + ", avgQpPerSec=" + this.avgQpPerSec + ", encoderFrameWidth=" + this.encoderFrameWidth + ", encoderFrameHeight=" + this.encoderFrameHeight + ", captureFrameWidth=" + this.captureFrameWidth + ", captureFrameHeight=" + this.captureFrameHeight + '}';
        }
    }

    public static class DingRtcRemoteVideoStats {
        public int decoderOutputFrameRate;
        public int packetLossRate;
        public int recvBitrate;
        public int rendererOutputFrameRate;
        public int stuckTime;
        public DingRtcVideoTrack track;
        public String userId;
        public int width = 0;
        public int height = 0;

        public String toString() {
            return "DingRtcRemoteVideoStats{userId='" + this.userId + "', track=" + this.track + ", width=" + this.width + ", height=" + this.height + ", recvBitrate=" + this.recvBitrate + ", decoderOutputFrameRate=" + this.decoderOutputFrameRate + ", rendererOutputFrameRate=" + this.rendererOutputFrameRate + ", packetLossRate=" + this.packetLossRate + ", stuckTime=" + this.stuckTime + '}';
        }
    }

    public static class DingRtcLocalAudioStats {
        public DingRtcAudioTrack track;
        public int sentBitrate = 0;
        public int sentSamplerate = 0;
        public int numChannel = 0;
        public int inputLevel = 0;

        public String toString() {
            return "DingRtcLocalAudioStats{track=" + this.track + ", sentBitrate=" + this.sentBitrate + ", sentSamplerate=" + this.sentSamplerate + ", numChannel=" + this.numChannel + ", inputLevel=" + this.inputLevel + '}';
        }

        public void convertIntToEnum(int value) {
            this.track = DingRtcAudioTrack.fromValue(value);
        }
    }

    public static class DingRtcRemoteAudioStats {
        public String userId;
        public int packetLossRate = 0;
        public int recvBitrate = 0;
        public int totalFrozenTime = 0;
        public int speechExpandRate = 0;

        public String toString() {
            return "DingRtcRemoteAudioStats{userId='" + this.userId + "', packetLossRate=" + this.packetLossRate + ", recvBitrate=" + this.recvBitrate + ", totalFrozenTime=" + this.totalFrozenTime + ", speechExpandRate=" + this.speechExpandRate + '}';
        }
    }

    public enum DingRtcAudioMixingStatus {
        DingRtcAudioMixingNone(0),
        DingRtcAudioMixingStarted(100),
        DingRtcAudioMixingStopped(101),
        DingRtcAudioMixingPaused(102),
        DingRtcAudioMixingResumed(103),
        DingRtcAudioMixingEnded(104),
        DingRtcAudioMixingBuffering(105),
        DingRtcAudioMixingBufferingEnd(106),
        DingRtcAudioMixingFailed(107);

        private final int value;

        DingRtcAudioMixingStatus(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcAudioMixingStatus fromNativeIndex(int index) {
            switch (index) {
                case 100:
                    DingRtcAudioMixingStatus ret = DingRtcAudioMixingStarted;
                    return ret;
                case 101:
                    DingRtcAudioMixingStatus ret2 = DingRtcAudioMixingStopped;
                    return ret2;
                case 102:
                    DingRtcAudioMixingStatus ret3 = DingRtcAudioMixingPaused;
                    return ret3;
                case 103:
                    DingRtcAudioMixingStatus ret4 = DingRtcAudioMixingResumed;
                    return ret4;
                case 104:
                    DingRtcAudioMixingStatus ret5 = DingRtcAudioMixingEnded;
                    return ret5;
                case 105:
                    DingRtcAudioMixingStatus ret6 = DingRtcAudioMixingBuffering;
                    return ret6;
                case 106:
                    DingRtcAudioMixingStatus ret7 = DingRtcAudioMixingBufferingEnd;
                    return ret7;
                case 107:
                    DingRtcAudioMixingStatus ret8 = DingRtcAudioMixingFailed;
                    return ret8;
                default:
                    DingRtcAudioMixingStatus ret9 = DingRtcAudioMixingNone;
                    return ret9;
            }
        }
    }

    public enum DingRtcAudioMixingErrorCode {
        DingRtcAudioMixingNoError(0),
        DingRtcAudioMixingOpenFailed(100),
        DingRtcAudioMixingDecodeFailed(101);

        private final int value;

        DingRtcAudioMixingErrorCode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcAudioMixingErrorCode fromNativeIndex(int index) {
            if (index == 100) {
                DingRtcAudioMixingErrorCode ret = DingRtcAudioMixingOpenFailed;
                return ret;
            }
            if (index == 101) {
                DingRtcAudioMixingErrorCode ret2 = DingRtcAudioMixingDecodeFailed;
                return ret2;
            }
            DingRtcAudioMixingErrorCode ret3 = DingRtcAudioMixingNoError;
            return ret3;
        }
    }

    public static class DingRtcAudioMixingStatusConfig {
        public long durationMs;
        public DingRtcAudioMixingErrorCode errorCode;
        public String fileName;
        public int id;
        public DingRtcAudioMixingStatus status;

        public String toString() {
            return "DingRtcAudioMixingStatusConfig{status=" + this.status + ", errorCode=" + this.errorCode + ", fileName=" + this.fileName + ", id=" + this.id + ", durationMs=" + this.durationMs + '}';
        }
    }

    public static class DingRtcAudioMixingConfig {
        public boolean enablePublish = false;
        public boolean enablePlayout = true;
        public int publishVolume = 100;
        public int playoutVolume = 100;
        public int cycles = 1;
        public long startPosMs = 0;

        public String toString() {
            return "DingRtcAudioMixingConfig{enablePublish=" + this.enablePublish + ", enablePlayout=" + this.enablePlayout + ", publishVolume=" + this.publishVolume + ", playoutVolume=" + this.playoutVolume + ", cycles=" + this.cycles + ", startPosMs=" + this.startPosMs + '}';
        }
    }

    public static class DingRtcAudioVolumeInfo {
        public String userId;
        public int volume = 0;
        public int speechState = 0;

        public String toString() {
            return "DingRtcAudioVolumeInfo{userId='" + this.userId + "', volume=" + this.volume + ", speechState=" + this.speechState + '}';
        }
    }

    public enum DingRtcVideoFormat {
        DingRtcVideoFormatI420(0),
        DingRtcVideoFormatNV12(1),
        DingRtcVideoFormatNV21(2),
        DingRtcVideoFormatBGRA(3),
        DingRtcVideoFormatARGB(4),
        DingRtcVideoFormatRGBA(5),
        DingRtcVideoFormatABGR(6),
        DingRtcVideoFormatTexture2D(7),
        DingRtcVideoFormatTextureOES(8);

        private final int val;

        DingRtcVideoFormat(int val) {
            this.val = val;
        }

        public int getValue() {
            return this.val;
        }

        public static DingRtcVideoFormat fromNativeIndex(int index) {
            try {
                DingRtcVideoFormat ret = values()[index];
                return ret;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
    }

    public static abstract class DingRtcVideoObserver {
        public boolean onLocalVideoSample(DingRtcVideoSourceType sourceType, DingRtcVideoSample videoSample) {
            return false;
        }

        public boolean onRemoteVideoSample(String callId, DingRtcVideoSourceType sourceType, DingRtcVideoSample videoSample) {
            return false;
        }

        public boolean onPreEncodeVideoFrame(DingRtcVideoSourceType sourceType, DingRtcVideoSample videoSample) {
            return false;
        }

        public DingRtcVideoFormat onGetVideoFormatPreference() {
            return DingRtcVideoFormat.DingRtcVideoFormatI420;
        }
    }

    public enum DingRtcConnectionStatus {
        DingRtcConnectionStatusInit(0),
        DingRtcConnectionStatusDisconnected(1),
        DingRtcConnectionStatusConnecting(2),
        DingRtcConnectionStatusConnected(3),
        DingRtcConnectionStatusReconnecting(4),
        DingRtcConnectionStatusFailed(5);

        private final int connectionStatus;

        DingRtcConnectionStatus(int connectionStatus) {
            this.connectionStatus = connectionStatus;
        }

        public int getValue() {
            return this.connectionStatus;
        }

        public static DingRtcConnectionStatus getDingRtcConnectionStatus(int status) {
            for (DingRtcConnectionStatus connectionStatus : values()) {
                if (connectionStatus.getValue() == status) {
                    return connectionStatus;
                }
            }
            return DingRtcConnectionStatusInit;
        }
    }

    public enum DingRtcConnectionStatusChangeReason {
        DingRtcConnectionChangedDummyReason(0),
        DingRtcConnectionChangedSignalingHeartbeatTimeout(1),
        DingRtcConnectionChangedSignalingHeartbeatAlive(2),
        DingRtcConnectionChangedSignalingJoinChannelFailure(3),
        DingRtcConnectionChangedSignalingJoinChannelSuccess(4),
        DingRtcConnectionChangedSignalingLeaveRoom(5),
        DingRtcConnectionChangedSignalingConnecting(6),
        DingRtcConnectionChangedMediaLinkChange(7),
        DingRtcConnectionChangedNetworkInterrupted(8),
        DingRtcConnectionChangedNetworkRecovery(9);

        private final int reason;

        DingRtcConnectionStatusChangeReason(int reason) {
            this.reason = reason;
        }

        public int getValue() {
            return this.reason;
        }

        public static DingRtcConnectionStatusChangeReason getConnectionStatusChangeReason(int reason) {
            for (DingRtcConnectionStatusChangeReason changeReason : values()) {
                if (changeReason.getValue() == reason) {
                    return changeReason;
                }
            }
            return DingRtcConnectionChangedDummyReason;
        }
    }

    public enum DingRtcVideoTrack {
        DingRtcVideoTrackNo(0),
        DingRtcVideoTrackCamera(1),
        DingRtcVideoTrackScreen(2),
        DingRtcVideoTrackBoth(3);

        private final int videoTrack;

        DingRtcVideoTrack(int videoTrack) {
            this.videoTrack = videoTrack;
        }

        public int getValue() {
            return this.videoTrack;
        }

        public static DingRtcVideoTrack fromValue(int videoTrack) {
            for (DingRtcVideoTrack DingRtcVideoTrack : values()) {
                if (DingRtcVideoTrack.getValue() == videoTrack) {
                    return DingRtcVideoTrack;
                }
            }
            return DingRtcVideoTrackNo;
        }
    }

    public enum DingRtcPublishState {
        DingRtcStatsPublishIdle(0),
        DingRtcStatsNoPublish(1),
        DingRtcStatsPublishing(2),
        DingRtcStatsPublished(3);

        private final int publishState;

        DingRtcPublishState(int publishState) {
            this.publishState = publishState;
        }

        public static DingRtcPublishState fromValue(int state) {
            for (DingRtcPublishState v : values()) {
                if (v.getValue() == state) {
                    return v;
                }
            }
            return null;
        }

        public int getValue() {
            return this.publishState;
        }
    }

    public enum DingRtcSubscribeState {
        DingRtcStatsSubscribeIdle(0),
        DingRtcStatsNoSubscribe(1),
        DingRtcStatsSubscribing(2),
        DingRtcStatsSubscribed(3);

        private final int subscribeState;

        DingRtcSubscribeState(int subscribeState) {
            this.subscribeState = subscribeState;
        }

        public static DingRtcSubscribeState fromValue(int state) {
            for (DingRtcSubscribeState v : values()) {
                if (v.getValue() == state) {
                    return v;
                }
            }
            return null;
        }

        public int getValue() {
            return this.subscribeState;
        }
    }

    public enum DingRtcUserOfflineReason {
        DingRtcUserOfflineQuit(0),
        DingRtcUserOfflineDropped(1),
        DingRtcUserOfflineBecomeAudience(2);

        private final int offlineReason;

        DingRtcUserOfflineReason(int reason) {
            this.offlineReason = reason;
        }

        public int getValue() {
            return this.offlineReason;
        }

        public static DingRtcUserOfflineReason fromValue(int val) {
            if (val == 1) {
                return DingRtcUserOfflineDropped;
            }
            if (val == 2) {
                return DingRtcUserOfflineBecomeAudience;
            }
            return DingRtcUserOfflineQuit;
        }
    }

    public enum DingRtcVideoStreamType {
        DingRtcVideoStreamTypeNone(0),
        DingRtcVideoStreamTypeFHD(1),
        DingRtcVideoStreamTypeHD(2),
        DingRtcVideoStreamTypeSD(3),
        DingRtcVideoStreamTypeLD(4);

        private final int videoStreamType;

        DingRtcVideoStreamType(int videoStreamType) {
            this.videoStreamType = videoStreamType;
        }

        public int getValue() {
            return this.videoStreamType;
        }

        public static DingRtcVideoStreamType fromValue(int videoStreamType) {
            for (DingRtcVideoStreamType DingRtcVideoStreamType : values()) {
                if (DingRtcVideoStreamType.getValue() == videoStreamType) {
                    return DingRtcVideoStreamType;
                }
            }
            return DingRtcVideoStreamTypeFHD;
        }
    }

    public enum DingRtcAudioTrack {
        DingRtcAudioTrackNo(0),
        DingRtcAudioTrackMic(1);

        private final int audioTrack;

        DingRtcAudioTrack(int audioTrack) {
            this.audioTrack = audioTrack;
        }

        public int getValue() {
            return this.audioTrack;
        }

        public static DingRtcAudioTrack fromValue(int i) {
            try {
                DingRtcAudioTrack ret = values()[i];
                return ret;
            } catch (Exception e) {
                DingRtcAudioTrack ret2 = DingRtcAudioTrackNo;
                return ret2;
            }
        }
    }

    public enum DingRtcNetworkQuality {
        DingRtcNetworkQualityGood(0),
        DingRtcNetworkQualityPoor(1),
        DingRtcNetworkQualityDisconnect(2),
        DingRtcNetworkQualityUnKnow(3);

        private final int transport;

        DingRtcNetworkQuality(int transport) {
            this.transport = transport;
        }

        public int getValue() {
            return this.transport;
        }

        public static DingRtcNetworkQuality getQuality(int status) {
            for (DingRtcNetworkQuality quality : values()) {
                if (quality.getValue() == status) {
                    return quality;
                }
            }
            return DingRtcNetworkQualityUnKnow;
        }
    }

    public enum DingRtcRenderMode {
        DingRtcRenderModeAuto(0),
        DingRtcRenderModeStretch(1),
        DingRtcRenderModeFill(2),
        DingRtcRenderModeCrop(3),
        DingRtcRenderModeNoChange(99);

        private final int renderMode;

        DingRtcRenderMode(int renderMode) {
            this.renderMode = renderMode;
        }

        public int getValue() {
            return this.renderMode;
        }
    }

    public enum DingRtcRenderMirrorMode {
        DingRtcRenderMirrorModeOnlyFront(0),
        DingRtcRenderMirrorModeAllEnabled(1),
        DingRtcRenderMirrorModeAllDisable(2);

        private final int value;

        DingRtcRenderMirrorMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcRotationMode {
        DingRtcRotationMode_0(0),
        DingRtcRotationMode_90(90),
        DingRtcRotationMode_180(JavaScreenCapturer.DEGREE_180),
        DingRtcRotationMode_270(JavaScreenCapturer.DEGREE_270);

        private final int value;

        DingRtcRotationMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcMirrorMode {
        DingRtcMirrorMode_Disable(0),
        DingRtcMirrorMode_Enable(1);

        private final int value;

        DingRtcMirrorMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcLogLevel {
        DingRtcLogLevelInfo(3),
        DingRtcLogLevelWarn(4),
        DingRtcLogLevelError(5),
        DingRtcLogLevelNone(6);

        private final int value;

        DingRtcLogLevel(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcAudioNumChannel {
        DingRtcMonoAudio(1),
        DingRtcStereoAudio(2);

        private final int value;

        DingRtcAudioNumChannel(int numChannel) {
            this.value = numChannel;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcAudioSampleRate {
        DingRtcAudioSampleRate_8000(0),
        DingRtcAudioSampleRate_16000(1),
        DingRtcAudioSampleRate_32000(2),
        DingRtcAudioSampleRate_44100(3),
        DingRtcAudioSampleRate_48000(4);

        private final int id;

        DingRtcAudioSampleRate(int id) {
            this.id = id;
        }

        public int getId() {
            return this.id;
        }
    }

    public enum DingRtcAudioProfile {
        DingRtcEngineBasicQualityMode(0),
        DingRtcEngineHighQualityMode(1),
        DingRtcEngineSuperHighQualityMode(2);

        private final int value;

        DingRtcAudioProfile(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcAudioScenario {
        DingRtcSceneDefaultMode(0),
        DingRtcSceneMusicMode(1);

        private final int value;

        DingRtcAudioScenario(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcMuteLocalAudioMode {
        DingRtcMuteAudioModeDefault(0),
        DingRtcMuteAllAudioMode(1),
        DingRtcMuteOnlyMicAudioMode(2),
        DingRtcMuteLocalAudioMax(3);

        private final int value;

        DingRtcMuteLocalAudioMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcScreenShareMode {
        DingRtcScreenShareNoneMode(0),
        DingRtcScreenShareOnlyVideoMode(1),
        DingRtcScreenShareOnlyAudioMode(2),
        DingRtcScreenShareAllMode(3);

        private final int value;

        DingRtcScreenShareMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcAudioFrameObserverOperationMode {
        DingRtcAudioDataObserverOperationModeReadOnly(0),
        DingRtcAudioDataObserverOperationModeWriteOnly(1),
        DingRtcAudioDataObserverOperationModeReadWrite(2);

        private final int value;

        DingRtcAudioFrameObserverOperationMode(int mode) {
            this.value = mode;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcAudioFrameObserverUserDefinedInfoBitMask {
        DingRtcAudioFrameObserverUserDefinedInfoBitMaskNone(0),
        DingRtcAudioFrameObserverUserDefinedInfoBitMaskMixExCapture(1),
        DingRtcAudioFrameObserverUserDefinedInfoBitMaskMixExRender(2);

        private final int value;

        DingRtcAudioFrameObserverUserDefinedInfoBitMask(int bitmask) {
            this.value = bitmask;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcAudioFramePermission {
        DingRtcAudioFramePermissionReadOnly(0),
        DingRtcAudioFramePermissionReadAndWrite(1);

        private final int value;

        DingRtcAudioFramePermission(int permission) {
            this.value = permission;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcEngineVirtualBackgroundMode {
        DingRtcEngineVirtualBackgroundBlur(0),
        DingRtcEngineVirtualBackgroundReplace(1);

        private final int value;

        DingRtcEngineVirtualBackgroundMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcOnByeType {
        DingRtcByeTypeKickOff(1),
        DingRtcByeTypeDelChannel(2),
        DingRtcByeTypeRestoreSession(3);

        private final int mOnByeType;

        DingRtcOnByeType(int type) {
            this.mOnByeType = type;
        }

        public static DingRtcOnByeType fromValue(int code) {
            for (DingRtcOnByeType t : values()) {
                if (t.getValue() == code) {
                    return t;
                }
            }
            return DingRtcByeTypeRestoreSession;
        }

        public int getValue() {
            return this.mOnByeType;
        }
    }

    public enum DingRtcAudioRouteType {
        DingRtcAudioRouteType_Default(0),
        DingRtcAudioRouteType_Headset(1),
        DingRtcAudioRouteType_Earpiece(2),
        DingRtcAudioRouteType_HeadsetNoMic(3),
        DingRtcAudioRouteType_Speakerphone(4),
        DingRtcAudioRouteType_LoudSpeaker(5),
        DingRtcAudioRouteType_BlueTooth(6);

        private final int val;

        DingRtcAudioRouteType(int val) {
            this.val = val;
        }

        public int getValue() {
            return this.val;
        }

        public static DingRtcAudioRouteType fromValue(int val) {
            for (DingRtcAudioRouteType type : values()) {
                if (type.getValue() == val) {
                    return type;
                }
            }
            return DingRtcAudioRouteType_Default;
        }
    }

    public static class DingRtcAudioDeviceInfo {
        public boolean isUsed;
        public String name;
        public DingRtcAudioRouteType type;

        public DingRtcAudioDeviceInfo(String name, DingRtcAudioRouteType type, boolean isUsed) {
            this.name = name;
            this.type = type;
            this.isUsed = isUsed;
        }

        public String toString() {
            return "DingRtcAudioDeviceInfo{name='" + this.name + "', type=" + this.type + ", isUsed=" + this.isUsed + '}';
        }
    }

    public static class DingRtcVideoDeviceInfo {
        public String deviceId;
        public DingRtcCameraDirection direction;
        public String name;

        public DingRtcVideoDeviceInfo(String name, String deviceId, DingRtcCameraDirection direction) {
            this.name = name;
            this.deviceId = deviceId;
            this.direction = direction;
        }

        public String toString() {
            return "DingRtcVideoDeviceInfo{name='" + this.name + "', id=" + this.deviceId + '}';
        }
    }

    public static class DingRtcVideoCanvas {
        public Object view;
        public int textureId = 0;
        public int textureWidth = 0;
        public int textureHeight = 0;
        public long sharedContext = 0;
        public boolean enableBeauty = false;
        public DingRtcRenderMode renderMode = DingRtcRenderMode.DingRtcRenderModeAuto;
        public DingRtcRenderMirrorMode mirrorMode = DingRtcRenderMirrorMode.DingRtcRenderMirrorModeOnlyFront;
        public DingRtcRotationMode rotationMode = DingRtcRotationMode.DingRtcRotationMode_0;
        public int backgroundColor = 0;
        boolean flip = false;
        boolean toBeRemoved = false;

        public String toString() {
            return "DingVideoCanvas{textureId=" + this.textureId + ", textureWidth=" + this.textureWidth + ", textureHeight=" + this.textureHeight + ", sharedContext=" + this.sharedContext + ", enableBeauty=" + this.enableBeauty + ", view=" + this.view + ", renderMode=" + this.renderMode + ", mirrorMode=" + this.mirrorMode + ", background=" + this.backgroundColor + ", flip=" + this.flip + ", toBeRemoved=" + this.toBeRemoved + '}';
        }
    }

    public enum DingRtcCameraDirection {
        CAMERA_INVALID(-1),
        CAMERA_REAR(0),
        CAMERA_FRONT(1);

        private final int value;

        DingRtcCameraDirection(int var3) {
            this.value = var3;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcCameraDirection getByValue(int type) {
            for (DingRtcCameraDirection t : values()) {
                if (t.value == type) {
                    return t;
                }
            }
            return CAMERA_INVALID;
        }
    }

    public enum DingRtcCaptureOutputPreference {
        DingRtc_CAPTURER_OUTPUT_PREFERENCE_AUTO(0),
        DingRtc_CAPTURER_OUTPUT_PREFERENCE_PERFORMANCE(1),
        DingRtc_CAPTURER_OUTPUT_PREFERENCE_PREVIEW(2);

        private final int value;

        DingRtcCaptureOutputPreference(int var3) {
            this.value = var3;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcVideoEncoderFrameRate {
        DingRtcVideoEncoderFrameRate_FPS_5(5),
        DingRtcVideoEncoderFrameRate_FPS_10(10),
        DingRtcVideoEncoderFrameRate_FPS_15(15),
        DingRtcVideoEncoderFrameRate_FPS_20(20),
        DingRtcVideoEncoderFrameRate_FPS_30(30);

        private final int value;

        DingRtcVideoEncoderFrameRate(int var) {
            this.value = var;
        }

        public int getValue() {
            return this.value;
        }
    }

    public enum DingRtcVideoEncoderOrientationMode {
        DingRtcVideoEncoderOrientationModeAdaptive(0),
        DingRtcVideoEncoderOrientationModeFixedLandscape(1),
        DingRtcVideoEncoderOrientationModeFixedPortrait(2);

        private final int value;

        DingRtcVideoEncoderOrientationMode(int var) {
            this.value = var;
        }

        public int getValue() {
            return this.value;
        }
    }

    public static class DingRtcVideoDimensions {
        public int height;
        public int width;

        public DingRtcVideoDimensions(int var1, int var2) {
            this.width = var1;
            this.height = var2;
        }

        public DingRtcVideoDimensions() {
            this.width = 640;
            this.height = 480;
        }
    }

    public static class DingRtcAudioGroupMember {
        public String uid;
        public String usrData;

        public String toString() {
            return "DingRtcAudioGroupMember{uid=" + this.uid + "usrData=" + this.usrData + '}';
        }
    }

    public static DingRtcEngine create(Context context, String extras) {
        return new RtcEngineImpl(context, extras);
    }

    public static void setLogLevel(DingRtcLogLevel logLevel) {
        Log.i(TAG, "[API]setLogLevel:" + logLevel);
        RtcEngineImpl.nativeSetLogLevel(logLevel.getValue());
    }

    public static int setLogDirPath(String logDirPath) {
        Log.i(TAG, "[API]setLogDirPath:" + logDirPath);
        return RtcEngineImpl.setLogPath(logDirPath);
    }

    public static String getSDKVersion() {
        return RtcEngineImpl.nativeGetSDKVersion();
    }

    public static String getSDKBuild() {
        return RtcEngineImpl.nativeGetSDKBuild();
    }

    public static String getErrorDescription(int errorCode) {
        return RtcEngineImpl.nativeErrorDescription(errorCode);
    }
}
