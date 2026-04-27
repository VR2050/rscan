package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class Camera1Session$$Lambda$1 implements VideoSink {
    private final Camera1Session arg$1;

    private Camera1Session$$Lambda$1(Camera1Session camera1Session) {
        this.arg$1 = camera1Session;
    }

    public static VideoSink lambdaFactory$(Camera1Session camera1Session) {
        return new Camera1Session$$Lambda$1(camera1Session);
    }

    @Override // org.webrtc.mozi.VideoSink
    public void onFrame(VideoFrame videoFrame) {
        Camera1Session.lambda$listenForTextureFrames$0(this.arg$1, videoFrame);
    }
}
