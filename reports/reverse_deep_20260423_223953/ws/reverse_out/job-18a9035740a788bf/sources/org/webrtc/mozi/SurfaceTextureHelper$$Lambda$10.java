package org.webrtc.mozi;

import android.graphics.SurfaceTexture;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class SurfaceTextureHelper$$Lambda$10 implements SurfaceTexture.OnFrameAvailableListener {
    private final SurfaceTextureHelper arg$1;

    private SurfaceTextureHelper$$Lambda$10(SurfaceTextureHelper surfaceTextureHelper) {
        this.arg$1 = surfaceTextureHelper;
    }

    public static SurfaceTexture.OnFrameAvailableListener lambdaFactory$(SurfaceTextureHelper surfaceTextureHelper) {
        return new SurfaceTextureHelper$$Lambda$10(surfaceTextureHelper);
    }

    @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
    public void onFrameAvailable(SurfaceTexture surfaceTexture) {
        this.arg$1.deliverTextureFrame();
    }
}
