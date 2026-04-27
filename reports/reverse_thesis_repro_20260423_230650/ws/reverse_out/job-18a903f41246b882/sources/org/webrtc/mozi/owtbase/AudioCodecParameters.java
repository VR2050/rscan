package org.webrtc.mozi.owtbase;

import org.webrtc.mozi.owtbase.MediaCodecs;

/* JADX INFO: loaded from: classes3.dex */
public final class AudioCodecParameters {
    public final int channelNum;
    public final MediaCodecs.AudioCodec name;
    public final int sampleRate;

    public AudioCodecParameters(MediaCodecs.AudioCodec codecName) {
        this.name = codecName;
        this.channelNum = 0;
        this.sampleRate = 0;
    }

    public AudioCodecParameters(MediaCodecs.AudioCodec codecName, int channelNum, int sampleRate) {
        this.name = codecName;
        this.channelNum = channelNum;
        this.sampleRate = sampleRate;
    }

    public int getChannelNum() {
        return this.channelNum;
    }

    public int getSampleRate() {
        return this.sampleRate;
    }

    public int getNameNative() {
        return this.name.ordinal();
    }
}
