package org.webrtc.mozi.owtbase;

import org.webrtc.mozi.owtbase.MediaCodecs;

/* JADX INFO: loaded from: classes3.dex */
public class AudioEncodingParameters {
    public final AudioCodecParameters codec;
    public int maxBitrate;

    public AudioEncodingParameters(MediaCodecs.AudioCodec codec) {
        this.maxBitrate = 0;
        this.codec = new AudioCodecParameters(codec);
    }

    public AudioEncodingParameters(AudioCodecParameters audioCodecParameters) {
        this.maxBitrate = 0;
        this.codec = audioCodecParameters;
    }

    public AudioEncodingParameters(AudioCodecParameters audioCodecParameters, int maxBitrateKbps) {
        this.maxBitrate = 0;
        this.codec = audioCodecParameters;
        this.maxBitrate = maxBitrateKbps;
    }

    public AudioCodecParameters getCodec() {
        return this.codec;
    }

    public int getMaxBitrate() {
        return this.maxBitrate;
    }
}
