package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class VP9Decoder extends WrappedNativeVideoDecoder {
    static native long nativeCreateDecoder();

    static native boolean nativeIsSupported();

    VP9Decoder() {
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public long createNativeVideoDecoder() {
        return nativeCreateDecoder();
    }
}
