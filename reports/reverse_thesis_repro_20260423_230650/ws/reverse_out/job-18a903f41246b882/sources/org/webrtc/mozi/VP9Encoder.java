package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class VP9Encoder extends WrappedNativeVideoEncoder {
    static native long nativeCreateEncoder();

    static native boolean nativeIsSupported();

    VP9Encoder() {
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public long createNativeVideoEncoder() {
        return nativeCreateEncoder();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public boolean isHardwareEncoder() {
        return false;
    }
}
