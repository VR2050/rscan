package org.webrtc.mozi;

import org.webrtc.mozi.video.grayconfig.MediaCodecGrayConfig;

/* JADX INFO: loaded from: classes3.dex */
public class McsConfigHelper {
    private long nativeOwtFactoryPtr;
    private final long nativePtr;
    private final SimulcastConfigHelper simulcastConfigHelper;

    private native void nativeEnableBbrWebrtc(long j, boolean z);

    private native AV1Config nativeGetAV1Config(long j);

    private native AndroidRoomsConfig nativeGetAndroidRoomsConfig(long j);

    private native AudioDeviceConfig nativeGetAudioDeviceConfig(long j);

    private native AudioTransportConfig nativeGetAudioTransportConfig(long j);

    private native AudioVolumeConfig nativeGetAudioVolumeConfig(long j);

    private native BWEConfig nativeGetBWEConfig(long j);

    private native BbrConfig nativeGetBbrConfig(long j);

    private native ConnectionTrialConfig nativeGetConnectionTrialConfig(long j);

    private native EndToEndDelayConfig nativeGetEndToEndDelayConfig(long j);

    private native GeneralSimulcastConfig nativeGetGeneralSimulcastConfig(long j);

    private native H264Config nativeGetH264Config(long j);

    private native HardwareInfoConfig nativeGetHardwareInfoConfig(long j);

    private native MediaCodecGrayConfig nativeGetMediaCodecGrayConfig(long j);

    private native MediaCodecLevelConfig nativeGetMediaCodecLevelConfig(long j);

    private native OnePCConfig nativeGetOnePCConfig(long j);

    private native OneRTCAudioConfig nativeGetOneRTCAudioConfig(long j);

    private native ProjectionConfig nativeGetProjectionConfig(long j);

    private native SdkConfig nativeGetSdkConfig(long j);

    private native SdpConfig nativeGetSdpConfig(long j);

    private native ServerBWEConfig nativeGetServerBWEConfig(long j);

    private native SignalConfig nativeGetSignalConfig(long j);

    private native SimulcastConfig nativeGetSimulcastConfig(long j);

    private native StatsConfig nativeGetStatsConfig(long j);

    private native StatsTrialConfig nativeGetStatsTrialConfig(long j);

    private native TurnRequestConfig nativeGetTurnRequestConfig(long j);

    private native VideoCodecConfig nativeGetVideoCodecConfig(long j);

    private native VideoFecConfig nativeGetVideoFecConfig(long j);

    private native VideoMediaCodecConfig nativeGetVideoMediaCodecConfig(long j);

    private native boolean nativeOneRTCNativeGrayConfigEnabled(long j);

    private native void nativeResetDefault(long j);

    @Deprecated
    private McsConfigHelper() {
        this.nativePtr = 0L;
        this.simulcastConfigHelper = new SimulcastConfigHelper(0L);
    }

    public McsConfigHelper(long nativePtr) {
        this.nativePtr = nativePtr;
        this.simulcastConfigHelper = new SimulcastConfigHelper(nativePtr);
    }

    public long getNativeMcsConfig() {
        return this.nativePtr;
    }

    public void setNativeOwtFactory(long owtFactory) {
        this.nativeOwtFactoryPtr = owtFactory;
    }

    public long getNativeOwtFactory() {
        return this.nativeOwtFactoryPtr;
    }

    public AudioDeviceConfig getAudioDeviceConfig() {
        return nativeGetAudioDeviceConfig(this.nativePtr);
    }

    public VideoMediaCodecConfig getVideoMediaCodecConfig() {
        return nativeGetVideoMediaCodecConfig(this.nativePtr);
    }

    public H264Config getH264Config() {
        return nativeGetH264Config(this.nativePtr);
    }

    public StatsConfig getStatsConfig() {
        return nativeGetStatsConfig(this.nativePtr);
    }

    public AudioTransportConfig getAudioTransportConfig() {
        return nativeGetAudioTransportConfig(this.nativePtr);
    }

    public SignalConfig getSignalConfig() {
        return nativeGetSignalConfig(this.nativePtr);
    }

    public AndroidRoomsConfig getAndroidRoomsConfig() {
        return nativeGetAndroidRoomsConfig(this.nativePtr);
    }

    public ProjectionConfig getProjectionConfig() {
        return nativeGetProjectionConfig(this.nativePtr);
    }

    public SdkConfig getSdkConfig() {
        return nativeGetSdkConfig(this.nativePtr);
    }

    public SimulcastConfig getSimulcastConfig() {
        return nativeGetSimulcastConfig(this.nativePtr);
    }

    public GeneralSimulcastConfig getGeneralSimulcastConfig() {
        return nativeGetGeneralSimulcastConfig(this.nativePtr);
    }

    public SimulcastConfigHelper getSimulcastConfigHelper() {
        return this.simulcastConfigHelper;
    }

    public EndToEndDelayConfig getEndToEndDelayConfig() {
        return nativeGetEndToEndDelayConfig(this.nativePtr);
    }

    public OnePCConfig getOnePCConfig() {
        return nativeGetOnePCConfig(this.nativePtr);
    }

    public BWEConfig getBWEConfig() {
        return nativeGetBWEConfig(this.nativePtr);
    }

    public AudioVolumeConfig getAudioVolumeConfig() {
        return nativeGetAudioVolumeConfig(this.nativePtr);
    }

    public HardwareInfoConfig getHardwareInfoConfig() {
        return nativeGetHardwareInfoConfig(this.nativePtr);
    }

    public OneRTCAudioConfig getOneRTCAudioConfig() {
        return nativeGetOneRTCAudioConfig(this.nativePtr);
    }

    public boolean oneRTCNativeGrayConfigEnabled() {
        return nativeOneRTCNativeGrayConfigEnabled(this.nativePtr);
    }

    public MediaCodecGrayConfig getMediaCodecGrayConfig() {
        return nativeGetMediaCodecGrayConfig(this.nativePtr);
    }

    public MediaCodecLevelConfig getMediaCodecLevelConfig() {
        return nativeGetMediaCodecLevelConfig(this.nativePtr);
    }

    public StatsTrialConfig getStatsTrialConfig() {
        return nativeGetStatsTrialConfig(this.nativePtr);
    }

    public BbrConfig getBbrConfig() {
        return nativeGetBbrConfig(this.nativePtr);
    }

    public void enableBbrWebrtc(boolean enable) {
        nativeEnableBbrWebrtc(this.nativePtr, enable);
    }

    public VideoFecConfig getVideoFecConfig() {
        return nativeGetVideoFecConfig(this.nativePtr);
    }

    public ConnectionTrialConfig getConnectionTrialConfig() {
        return nativeGetConnectionTrialConfig(this.nativePtr);
    }

    public VideoCodecConfig getVideoCodecConfig() {
        return nativeGetVideoCodecConfig(this.nativePtr);
    }

    public AV1Config getAV1Config() {
        return nativeGetAV1Config(this.nativePtr);
    }

    public ServerBWEConfig getServerBWEConfig() {
        return nativeGetServerBWEConfig(this.nativePtr);
    }

    public TurnRequestConfig getTurnRequestConfig() {
        return nativeGetTurnRequestConfig(this.nativePtr);
    }

    public SdpConfig getSdpConfig() {
        return nativeGetSdpConfig(this.nativePtr);
    }

    public void resetDefault() {
        nativeResetDefault(this.nativePtr);
    }
}
