package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceTextureHelper$$Lambda$3 implements Runnable {
    private final SurfaceTextureHelper arg$1;
    private final int arg$2;
    private final int arg$3;

    private SurfaceTextureHelper$$Lambda$3(SurfaceTextureHelper surfaceTextureHelper, int i, int i2) {
        this.arg$1 = surfaceTextureHelper;
        this.arg$2 = i;
        this.arg$3 = i2;
    }

    public static Runnable lambdaFactory$(SurfaceTextureHelper surfaceTextureHelper, int i, int i2) {
        return new SurfaceTextureHelper$$Lambda$3(surfaceTextureHelper, i, i2);
    }

    @Override // java.lang.Runnable
    public void run() {
        SurfaceTextureHelper.lambda$setTextureSize$10(this.arg$1, this.arg$2, this.arg$3);
    }
}
