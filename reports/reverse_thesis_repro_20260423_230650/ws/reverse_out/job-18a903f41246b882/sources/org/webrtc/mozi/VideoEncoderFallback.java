package org.webrtc.mozi;

import org.webrtc.mozi.VideoEncoder;

/* JADX INFO: loaded from: classes3.dex */
public class VideoEncoderFallback extends WrappedNativeVideoEncoder {
    private final VideoEncoder fallback;
    private final McsConfigHelper mcsConfigHelper;
    private final VideoEncoder primary;

    private static native long nativeCreateEncoder(VideoEncoder videoEncoder, VideoEncoder videoEncoder2, long j);

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ void decideToFallback() {
        super.decideToFallback();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoCodecStatus encode(VideoFrame videoFrame, VideoEncoder.EncodeInfo encodeInfo) {
        return super.encode(videoFrame, encodeInfo);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ String getImplementationName() {
        return super.getImplementationName();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ String getImplementationName2() {
        return super.getImplementationName2();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ String getProfileLevel() {
        return super.getProfileLevel();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoEncoder.ScalingSettings getScalingSettings() {
        return super.getScalingSettings();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoCodecStatus initEncode(VideoEncoder.Settings settings, VideoEncoder.Callback callback) {
        return super.initEncode(settings, callback);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoCodecStatus release() {
        return super.release();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ int setAdaptedFramerateRatio(int i, int i2, int i3) {
        return super.setAdaptedFramerateRatio(i, i2, i3);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoCodecStatus setChannelParameters(short s, long j) {
        return super.setChannelParameters(s, j);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoCodecStatus setRateAllocation(VideoEncoder.BitrateAllocation bitrateAllocation, int i) {
        return super.setRateAllocation(bitrateAllocation, i);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ void turnOffLayer(int i) {
        super.turnOffLayer(i);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ void turnOnLayer(int i) {
        super.turnOnLayer(i);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public /* bridge */ /* synthetic */ VideoCodecStatus updateSimulcastConfig(VideoEncoder.LayerSetting[] layerSettingArr) {
        return super.updateSimulcastConfig(layerSettingArr);
    }

    public VideoEncoderFallback(VideoEncoder fallback, VideoEncoder primary, McsConfigHelper mcsConfigHelper) {
        this.fallback = fallback;
        this.primary = primary;
        this.mcsConfigHelper = mcsConfigHelper;
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public long createNativeVideoEncoder() {
        return nativeCreateEncoder(this.fallback, this.primary, this.mcsConfigHelper.getNativeOwtFactory());
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public boolean isHardwareEncoder() {
        return this.primary.isHardwareEncoder();
    }
}
