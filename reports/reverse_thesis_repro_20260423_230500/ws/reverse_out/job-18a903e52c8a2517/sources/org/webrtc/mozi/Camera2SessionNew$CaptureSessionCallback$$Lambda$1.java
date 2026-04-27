package org.webrtc.mozi;

import org.webrtc.mozi.Camera2SessionNew;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class Camera2SessionNew$CaptureSessionCallback$$Lambda$1 implements VideoSink {
    private final Camera2SessionNew.CaptureSessionCallback arg$1;

    private Camera2SessionNew$CaptureSessionCallback$$Lambda$1(Camera2SessionNew.CaptureSessionCallback captureSessionCallback) {
        this.arg$1 = captureSessionCallback;
    }

    public static VideoSink lambdaFactory$(Camera2SessionNew.CaptureSessionCallback captureSessionCallback) {
        return new Camera2SessionNew$CaptureSessionCallback$$Lambda$1(captureSessionCallback);
    }

    @Override // org.webrtc.mozi.VideoSink
    public void onFrame(VideoFrame videoFrame) {
        Camera2SessionNew.CaptureSessionCallback.lambda$onConfigured$6(this.arg$1, videoFrame);
    }
}
