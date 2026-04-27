package org.webrtc.mozi;

import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class VideoFileRenderer$$Lambda$3 implements Runnable {
    private final VideoFileRenderer arg$1;
    private final CountDownLatch arg$2;

    private VideoFileRenderer$$Lambda$3(VideoFileRenderer videoFileRenderer, CountDownLatch countDownLatch) {
        this.arg$1 = videoFileRenderer;
        this.arg$2 = countDownLatch;
    }

    public static Runnable lambdaFactory$(VideoFileRenderer videoFileRenderer, CountDownLatch countDownLatch) {
        return new VideoFileRenderer$$Lambda$3(videoFileRenderer, countDownLatch);
    }

    @Override // java.lang.Runnable
    public void run() {
        VideoFileRenderer.lambda$release$2(this.arg$1, this.arg$2);
    }
}
