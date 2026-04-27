package org.webrtc.mozi.owtbase;

import org.webrtc.mozi.owtbase.MediaCodecs;

/* JADX INFO: loaded from: classes3.dex */
public final class VideoEncodingParameters {
    public final VideoCodecParameters codec;
    public boolean hardware;
    public int maxBitrate;

    public VideoEncodingParameters(MediaCodecs.VideoCodec codec) {
        this.maxBitrate = 0;
        this.codec = new VideoCodecParameters(codec);
    }

    public VideoEncodingParameters(VideoCodecParameters videoCodecParameters) {
        this.maxBitrate = 0;
        this.codec = videoCodecParameters;
    }

    public VideoEncodingParameters(VideoCodecParameters videoCodecParameters, int maxBitrateKbps) {
        this.maxBitrate = 0;
        this.codec = videoCodecParameters;
        this.maxBitrate = maxBitrateKbps;
    }

    public int getMaxBitrate() {
        return this.maxBitrate;
    }

    public VideoCodecParameters getCodec() {
        return this.codec;
    }

    public boolean isHardware() {
        return this.hardware;
    }
}
