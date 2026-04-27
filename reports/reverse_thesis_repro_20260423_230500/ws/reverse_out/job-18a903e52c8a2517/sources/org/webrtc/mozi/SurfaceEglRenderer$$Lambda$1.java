package org.webrtc.mozi;

import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceEglRenderer$$Lambda$1 implements Runnable {
    private final CountDownLatch arg$1;

    private SurfaceEglRenderer$$Lambda$1(CountDownLatch countDownLatch) {
        this.arg$1 = countDownLatch;
    }

    public static Runnable lambdaFactory$(CountDownLatch countDownLatch) {
        return new SurfaceEglRenderer$$Lambda$1(countDownLatch);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.countDown();
    }
}
