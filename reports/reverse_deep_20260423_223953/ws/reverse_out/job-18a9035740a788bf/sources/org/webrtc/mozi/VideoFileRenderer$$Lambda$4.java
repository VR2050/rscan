package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class VideoFileRenderer$$Lambda$4 implements Runnable {
    private final VideoFileRenderer arg$1;

    private VideoFileRenderer$$Lambda$4(VideoFileRenderer videoFileRenderer) {
        this.arg$1 = videoFileRenderer;
    }

    public static Runnable lambdaFactory$(VideoFileRenderer videoFileRenderer) {
        return new VideoFileRenderer$$Lambda$4(videoFileRenderer);
    }

    @Override // java.lang.Runnable
    public void run() {
        VideoFileRenderer.lambda$release$3(this.arg$1);
    }
}
