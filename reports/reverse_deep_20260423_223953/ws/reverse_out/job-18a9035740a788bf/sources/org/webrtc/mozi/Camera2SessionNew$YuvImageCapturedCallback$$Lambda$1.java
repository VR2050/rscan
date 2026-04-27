package org.webrtc.mozi;

import org.webrtc.mozi.Camera2SessionNew;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class Camera2SessionNew$YuvImageCapturedCallback$$Lambda$1 implements Runnable {
    private final Camera2SessionNew.YuvImageCapturedCallback arg$1;

    private Camera2SessionNew$YuvImageCapturedCallback$$Lambda$1(Camera2SessionNew.YuvImageCapturedCallback yuvImageCapturedCallback) {
        this.arg$1 = yuvImageCapturedCallback;
    }

    public static Runnable lambdaFactory$(Camera2SessionNew.YuvImageCapturedCallback yuvImageCapturedCallback) {
        return new Camera2SessionNew$YuvImageCapturedCallback$$Lambda$1(yuvImageCapturedCallback);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.imageInUsed = false;
    }
}
