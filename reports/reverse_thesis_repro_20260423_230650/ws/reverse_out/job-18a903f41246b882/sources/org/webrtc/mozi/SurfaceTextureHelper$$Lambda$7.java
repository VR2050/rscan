package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceTextureHelper$$Lambda$7 implements Runnable {
    private final SurfaceTextureHelper arg$1;

    private SurfaceTextureHelper$$Lambda$7(SurfaceTextureHelper surfaceTextureHelper) {
        this.arg$1 = surfaceTextureHelper;
    }

    public static Runnable lambdaFactory$(SurfaceTextureHelper surfaceTextureHelper) {
        return new SurfaceTextureHelper$$Lambda$7(surfaceTextureHelper);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.returnTextureFrame();
    }
}
