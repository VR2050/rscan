package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$7 implements Runnable {
    private final EglRenderer arg$1;
    private final Runnable arg$2;

    private EglRenderer$$Lambda$7(EglRenderer eglRenderer, Runnable runnable) {
        this.arg$1 = eglRenderer;
        this.arg$2 = runnable;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, Runnable runnable) {
        return new EglRenderer$$Lambda$7(eglRenderer, runnable);
    }

    @Override // java.lang.Runnable
    public void run() {
        EglRenderer.lambda$releaseEglSurface$5(this.arg$1, this.arg$2);
    }
}
