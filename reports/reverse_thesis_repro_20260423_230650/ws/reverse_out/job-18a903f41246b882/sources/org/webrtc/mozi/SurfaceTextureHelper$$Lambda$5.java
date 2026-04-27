package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceTextureHelper$$Lambda$5 implements Runnable {
    private final SurfaceTextureHelper arg$1;
    private final int arg$2;

    private SurfaceTextureHelper$$Lambda$5(SurfaceTextureHelper surfaceTextureHelper, int i) {
        this.arg$1 = surfaceTextureHelper;
        this.arg$2 = i;
    }

    public static Runnable lambdaFactory$(SurfaceTextureHelper surfaceTextureHelper, int i) {
        return new SurfaceTextureHelper$$Lambda$5(surfaceTextureHelper, i);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.frameRotation = this.arg$2;
    }
}
