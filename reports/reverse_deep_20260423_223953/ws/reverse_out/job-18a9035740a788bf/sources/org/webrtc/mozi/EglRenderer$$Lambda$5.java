package org.webrtc.mozi;

import java.util.concurrent.CountDownLatch;
import org.webrtc.mozi.EglRenderer;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$5 implements Runnable {
    private final EglRenderer arg$1;
    private final CountDownLatch arg$2;
    private final EglRenderer.FrameListener arg$3;

    private EglRenderer$$Lambda$5(EglRenderer eglRenderer, CountDownLatch countDownLatch, EglRenderer.FrameListener frameListener) {
        this.arg$1 = eglRenderer;
        this.arg$2 = countDownLatch;
        this.arg$3 = frameListener;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, CountDownLatch countDownLatch, EglRenderer.FrameListener frameListener) {
        return new EglRenderer$$Lambda$5(eglRenderer, countDownLatch, frameListener);
    }

    @Override // java.lang.Runnable
    public void run() {
        EglRenderer.lambda$removeFrameListener$4(this.arg$1, this.arg$2, this.arg$3);
    }
}
