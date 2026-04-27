package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceTextureHelper$$Lambda$9 implements Runnable {
    private final SurfaceTextureHelper arg$1;

    private SurfaceTextureHelper$$Lambda$9(SurfaceTextureHelper surfaceTextureHelper) {
        this.arg$1 = surfaceTextureHelper;
    }

    public static Runnable lambdaFactory$(SurfaceTextureHelper surfaceTextureHelper) {
        return new SurfaceTextureHelper$$Lambda$9(surfaceTextureHelper);
    }

    @Override // java.lang.Runnable
    public void run() {
        SurfaceTextureHelper.lambda$recycle$16(this.arg$1);
    }
}
