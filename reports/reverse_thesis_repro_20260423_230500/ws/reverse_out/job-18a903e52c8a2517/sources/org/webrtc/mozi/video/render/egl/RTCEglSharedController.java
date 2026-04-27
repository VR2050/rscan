package org.webrtc.mozi.video.render.egl;

import android.os.Handler;
import org.webrtc.mozi.EglBase14;

/* JADX INFO: loaded from: classes3.dex */
public class RTCEglSharedController extends RTCEglControlAdapter {
    private RTCEglController mEglResource;
    private ReleaseCallback mReleaseCallback;

    interface ReleaseCallback {
        void onRelease(RTCEglSharedController rTCEglSharedController);
    }

    public RTCEglSharedController(RTCEglController eglResource) {
        this.mEglResource = eglResource;
        if (eglResource.getEglBase() instanceof EglBase14) {
            this.mEglBase = new EglBase14((EglBase14) this.mEglResource.getEglBase());
            this.mEglBase.setTraceId("RTCEglSharedController");
            return;
        }
        throw new IllegalArgumentException("eglResource should have an EglBase14");
    }

    public void setReleaseCallback(ReleaseCallback callback) {
        this.mReleaseCallback = callback;
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void release() {
        releaseSurface();
        ReleaseCallback releaseCallback = this.mReleaseCallback;
        if (releaseCallback != null) {
            releaseCallback.onRelease(this);
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public Handler getRenderHandler(String name) {
        return this.mEglResource.getRenderHandler(name);
    }
}
