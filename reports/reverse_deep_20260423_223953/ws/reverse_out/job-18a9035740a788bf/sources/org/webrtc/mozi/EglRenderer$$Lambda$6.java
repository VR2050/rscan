package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$6 implements Runnable {
    private final EglRenderer arg$1;

    private EglRenderer$$Lambda$6(EglRenderer eglRenderer) {
        this.arg$1 = eglRenderer;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer) {
        return new EglRenderer$$Lambda$6(eglRenderer);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.renderFrameOnRenderThread();
    }
}
