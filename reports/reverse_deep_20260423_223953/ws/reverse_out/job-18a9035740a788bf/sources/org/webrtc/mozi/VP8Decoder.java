package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class VP8Decoder extends WrappedNativeVideoDecoder {
    static native long nativeCreateDecoder();

    VP8Decoder() {
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public long createNativeVideoDecoder() {
        return nativeCreateDecoder();
    }
}
