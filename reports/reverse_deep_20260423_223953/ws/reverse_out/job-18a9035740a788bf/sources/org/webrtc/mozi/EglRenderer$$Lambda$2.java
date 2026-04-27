package org.webrtc.mozi;

import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$2 implements Runnable {
    private final EglRenderer arg$1;
    private final CountDownLatch arg$2;

    private EglRenderer$$Lambda$2(EglRenderer eglRenderer, CountDownLatch countDownLatch) {
        this.arg$1 = eglRenderer;
        this.arg$2 = countDownLatch;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, CountDownLatch countDownLatch) {
        return new EglRenderer$$Lambda$2(eglRenderer, countDownLatch);
    }

    @Override // java.lang.Runnable
    public void run() {
        EglRenderer.lambda$release$1(this.arg$1, this.arg$2);
    }
}
