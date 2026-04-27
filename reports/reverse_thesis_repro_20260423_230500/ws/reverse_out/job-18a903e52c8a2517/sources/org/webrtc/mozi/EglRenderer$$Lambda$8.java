package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$8 implements Runnable {
    private final EglRenderer arg$1;
    private final float arg$2;
    private final float arg$3;
    private final float arg$4;
    private final float arg$5;

    private EglRenderer$$Lambda$8(EglRenderer eglRenderer, float f, float f2, float f3, float f4) {
        this.arg$1 = eglRenderer;
        this.arg$2 = f;
        this.arg$3 = f2;
        this.arg$4 = f3;
        this.arg$5 = f4;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, float f, float f2, float f3, float f4) {
        return new EglRenderer$$Lambda$8(eglRenderer, f, f2, f3, f4);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.clearSurfaceOnRenderThread(this.arg$2, this.arg$3, this.arg$4, this.arg$5);
    }
}
