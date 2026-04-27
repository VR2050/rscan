package org.webrtc.mozi;

import org.webrtc.mozi.VideoEncoder;

/* JADX INFO: loaded from: classes3.dex */
abstract class WrappedNativeVideoEncoder implements VideoEncoder {
    @Override // org.webrtc.mozi.VideoEncoder
    public abstract long createNativeVideoEncoder();

    @Override // org.webrtc.mozi.VideoEncoder
    public abstract boolean isHardwareEncoder();

    WrappedNativeVideoEncoder() {
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus initEncode(VideoEncoder.Settings settings, VideoEncoder.Callback encodeCallback) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus release() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus encode(VideoFrame frame, VideoEncoder.EncodeInfo info) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus setChannelParameters(short packetLoss, long roundTripTimeMs) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus setRateAllocation(VideoEncoder.BitrateAllocation allocation, int framerate) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public int setAdaptedFramerateRatio(int index, int denominator, int numerator) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus updateSimulcastConfig(VideoEncoder.LayerSetting[] layers) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public void turnOffLayer(int layer) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public void turnOnLayer(int layer) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoEncoder.ScalingSettings getScalingSettings() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public String getImplementationName() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public String getImplementationName2() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public void decideToFallback() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public String getProfileLevel() {
        throw new UnsupportedOperationException("Not implemented.");
    }
}
