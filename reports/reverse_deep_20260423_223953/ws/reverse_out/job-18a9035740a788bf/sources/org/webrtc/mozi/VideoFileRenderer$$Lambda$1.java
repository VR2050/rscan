package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class VideoFileRenderer$$Lambda$1 implements Runnable {
    private final VideoFileRenderer arg$1;
    private final VideoFrame arg$2;

    private VideoFileRenderer$$Lambda$1(VideoFileRenderer videoFileRenderer, VideoFrame videoFrame) {
        this.arg$1 = videoFileRenderer;
        this.arg$2 = videoFrame;
    }

    public static Runnable lambdaFactory$(VideoFileRenderer videoFileRenderer, VideoFrame videoFrame) {
        return new VideoFileRenderer$$Lambda$1(videoFileRenderer, videoFrame);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.renderFrameOnRenderThread(this.arg$2);
    }
}
