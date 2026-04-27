package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class AV1Encoder extends WrappedNativeVideoEncoder {
    static native long nativeCreateEncoder();

    static native boolean nativeIsSupported();

    AV1Encoder() {
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
