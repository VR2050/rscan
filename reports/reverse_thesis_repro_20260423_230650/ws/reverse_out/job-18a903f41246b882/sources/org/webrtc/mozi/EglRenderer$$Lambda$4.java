package org.webrtc.mozi;

import org.webrtc.mozi.EglRenderer;
import org.webrtc.mozi.RendererCommon;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class EglRenderer$$Lambda$4 implements Runnable {
    private final EglRenderer arg$1;
    private final RendererCommon.GlDrawer arg$2;
    private final EglRenderer.FrameListener arg$3;
    private final float arg$4;
    private final boolean arg$5;

    private EglRenderer$$Lambda$4(EglRenderer eglRenderer, RendererCommon.GlDrawer glDrawer, EglRenderer.FrameListener frameListener, float f, boolean z) {
        this.arg$1 = eglRenderer;
        this.arg$2 = glDrawer;
        this.arg$3 = frameListener;
        this.arg$4 = f;
        this.arg$5 = z;
    }

    public static Runnable lambdaFactory$(EglRenderer eglRenderer, RendererCommon.GlDrawer glDrawer, EglRenderer.FrameListener frameListener, float f, boolean z) {
        return new EglRenderer$$Lambda$4(eglRenderer, glDrawer, frameListener, f, z);
    }

    @Override // java.lang.Runnable
    public void run() {
        EglRenderer.lambda$addFrameListener$3(this.arg$1, this.arg$2, this.arg$3, this.arg$4, this.arg$5);
    }
}
