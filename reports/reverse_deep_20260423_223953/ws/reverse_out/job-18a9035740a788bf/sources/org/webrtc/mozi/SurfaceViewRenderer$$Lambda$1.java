package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceViewRenderer$$Lambda$1 implements Runnable {
    private final SurfaceViewRenderer arg$1;
    private final int arg$2;
    private final int arg$3;

    private SurfaceViewRenderer$$Lambda$1(SurfaceViewRenderer surfaceViewRenderer, int i, int i2) {
        this.arg$1 = surfaceViewRenderer;
        this.arg$2 = i;
        this.arg$3 = i2;
    }

    public static Runnable lambdaFactory$(SurfaceViewRenderer surfaceViewRenderer, int i, int i2) {
        return new SurfaceViewRenderer$$Lambda$1(surfaceViewRenderer, i, i2);
    }

    @Override // java.lang.Runnable
    public void run() {
        SurfaceViewRenderer.lambda$onFrameResolutionChanged$0(this.arg$1, this.arg$2, this.arg$3);
    }
}
