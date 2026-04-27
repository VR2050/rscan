package org.webrtc.mozi.owtbase;

import org.webrtc.mozi.owtbase.MediaCodecs;

/* JADX INFO: loaded from: classes3.dex */
public final class VideoCodecParameters {
    public final MediaCodecs.VideoCodec name;
    public final MediaCodecs.H264Profile profile;

    public VideoCodecParameters(MediaCodecs.VideoCodec codecName) {
        this.name = codecName;
        this.profile = null;
    }

    public VideoCodecParameters(MediaCodecs.VideoCodec codecName, MediaCodecs.H264Profile profile) {
        this.name = codecName;
        this.profile = profile;
    }

    public MediaCodecs.VideoCodec getName() {
        return this.name;
    }

    public MediaCodecs.H264Profile getProfile() {
        return this.profile;
    }

    public int getNameNative() {
        return this.name.ordinal();
    }

    public String getProfileNative() {
        return this.profile.profile;
    }
}
