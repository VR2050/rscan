package org.webrtc.mozi;

import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class VideoFileRenderer$$Lambda$2 implements Runnable {
    private final VideoFileRenderer arg$1;
    private final VideoFrame.I420Buffer arg$2;
    private final VideoFrame arg$3;

    private VideoFileRenderer$$Lambda$2(VideoFileRenderer videoFileRenderer, VideoFrame.I420Buffer i420Buffer, VideoFrame videoFrame) {
        this.arg$1 = videoFileRenderer;
        this.arg$2 = i420Buffer;
        this.arg$3 = videoFrame;
    }

    public static Runnable lambdaFactory$(VideoFileRenderer videoFileRenderer, VideoFrame.I420Buffer i420Buffer, VideoFrame videoFrame) {
        return new VideoFileRenderer$$Lambda$2(videoFileRenderer, i420Buffer, videoFrame);
    }

    @Override // java.lang.Runnable
    public void run() {
        VideoFileRenderer.lambda$renderFrameOnRenderThread$1(this.arg$1, this.arg$2, this.arg$3);
    }
}
