package org.webrtc.mozi;

import android.os.Looper;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$3 implements Runnable {
    private final EglRenderer arg$1;
    private final Looper arg$2;
    private final boolean arg$3;

    private EglRenderer$$Lambda$3(EglRenderer eglRenderer, Looper looper, boolean z) {
        this.arg$1 = eglRenderer;
        this.arg$2 = looper;
        this.arg$3 = z;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, Looper looper, boolean z) {
        return new EglRenderer$$Lambda$3(eglRenderer, looper, z);
    }

    @Override // java.lang.Runnable
    public void run() {
        EglRenderer.lambda$release$2(this.arg$1, this.arg$2, this.arg$3);
    }
}
