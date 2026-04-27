package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceTextureHelper$$Lambda$8 implements Runnable {
    private final SurfaceTextureHelper arg$1;

    private SurfaceTextureHelper$$Lambda$8(SurfaceTextureHelper surfaceTextureHelper) {
        this.arg$1 = surfaceTextureHelper;
    }

    public static Runnable lambdaFactory$(SurfaceTextureHelper surfaceTextureHelper) {
        return new SurfaceTextureHelper$$Lambda$8(surfaceTextureHelper);
    }

    @Override // java.lang.Runnable
    public void run() {
        SurfaceTextureHelper.lambda$reuse$15(this.arg$1);
    }
}
