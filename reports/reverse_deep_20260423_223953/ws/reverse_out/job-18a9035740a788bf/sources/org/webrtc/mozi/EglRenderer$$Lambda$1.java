package org.webrtc.mozi;

import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$1 implements Runnable {
    private final EglRenderer arg$1;
    private final EglBase.Context arg$2;
    private final int[] arg$3;

    private EglRenderer$$Lambda$1(EglRenderer eglRenderer, EglBase.Context context, int[] iArr) {
        this.arg$1 = eglRenderer;
        this.arg$2 = context;
        this.arg$3 = iArr;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, EglBase.Context context, int[] iArr) {
        return new EglRenderer$$Lambda$1(eglRenderer, context, iArr);
    }

    @Override // java.lang.Runnable
    public void run() {
        EglRenderer.lambda$init$0(this.arg$1, this.arg$2, this.arg$3);
    }
}
