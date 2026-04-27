package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class H264Decoder extends WrappedNativeVideoDecoder {
    static native long nativeCreateDecoder();

    H264Decoder() {
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public long createNativeVideoDecoder() {
        return nativeCreateDecoder();
    }
}
