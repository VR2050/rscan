package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class Camera1Session$$Lambda$2 implements Runnable {
    private final Camera1Session arg$1;
    private final float arg$2;

    private Camera1Session$$Lambda$2(Camera1Session camera1Session, float f) {
        this.arg$1 = camera1Session;
        this.arg$2 = f;
    }

    public static Runnable lambdaFactory$(Camera1Session camera1Session, float f) {
        return new Camera1Session$$Lambda$2(camera1Session, f);
    }

    @Override // java.lang.Runnable
    public void run() {
        Camera1Session.lambda$setCameraExposureValue$3(this.arg$1, this.arg$2);
    }
}
