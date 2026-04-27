package org.webrtc.mozi;

import org.webrtc.mozi.Camera2Session;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class Camera2Session$CaptureSessionCallback$$Lambda$1 implements VideoSink {
    private final Camera2Session.CaptureSessionCallback arg$1;

    private Camera2Session$CaptureSessionCallback$$Lambda$1(Camera2Session.CaptureSessionCallback captureSessionCallback) {
        this.arg$1 = captureSessionCallback;
    }

    public static VideoSink lambdaFactory$(Camera2Session.CaptureSessionCallback captureSessionCallback) {
        return new Camera2Session$CaptureSessionCallback$$Lambda$1(captureSessionCallback);
    }

    @Override // org.webrtc.mozi.VideoSink
    public void onFrame(VideoFrame videoFrame) {
        Camera2Session.CaptureSessionCallback.lambda$onConfigured$4(this.arg$1, videoFrame);
    }
}
