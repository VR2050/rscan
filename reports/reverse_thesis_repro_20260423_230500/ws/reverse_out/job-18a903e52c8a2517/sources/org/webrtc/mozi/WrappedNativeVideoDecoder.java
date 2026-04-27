package org.webrtc.mozi;

import org.webrtc.mozi.VideoDecoder;

/* JADX INFO: loaded from: classes3.dex */
abstract class WrappedNativeVideoDecoder implements VideoDecoder {
    @Override // org.webrtc.mozi.VideoDecoder
    public abstract long createNativeVideoDecoder();

    WrappedNativeVideoDecoder() {
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public VideoCodecStatus initDecode(VideoDecoder.Settings settings, VideoDecoder.Callback decodeCallback) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public VideoCodecStatus release() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public VideoCodecStatus decode(EncodedImage frame, VideoDecoder.DecodeInfo info) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public boolean getPrefersLateDecoding() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public String getImplementationName() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public String getImplementationName2() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public String getCodecProfiles() {
        throw new UnsupportedOperationException("Not implemented.");
    }
}
