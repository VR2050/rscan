package org.webrtc.mozi.p2p;

/* JADX INFO: loaded from: classes3.dex */
public class CallbackWrapper implements Callback {
    private long mNativePtr;

    private static native void nativeOnFailure(long j, int i, String str);

    private static native void nativeOnSuccess(long j);

    public CallbackWrapper(long nativePtr) {
        this.mNativePtr = nativePtr;
    }

    @Override // org.webrtc.mozi.p2p.Callback
    public void onSuccess() {
        nativeOnSuccess(this.mNativePtr);
    }

    @Override // org.webrtc.mozi.p2p.Callback
    public void onFailure(int code, String msg) {
        nativeOnFailure(this.mNativePtr, code, msg);
    }
}
