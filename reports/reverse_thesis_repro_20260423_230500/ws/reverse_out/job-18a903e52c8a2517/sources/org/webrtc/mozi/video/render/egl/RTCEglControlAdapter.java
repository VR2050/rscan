package org.webrtc.mozi.video.render.egl;

import android.graphics.SurfaceTexture;
import android.view.Surface;
import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public abstract class RTCEglControlAdapter implements RTCEglController {
    protected EglBase mEglBase;
    protected String name;

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void createSurface(Surface surface) {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.createSurface(surface);
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void createSurface(SurfaceTexture surfaceTexture) {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.createSurface(surfaceTexture);
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public boolean hasSurface() {
        EglBase eglBase = this.mEglBase;
        return eglBase != null && eglBase.hasSurface();
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public int surfaceWidth() {
        EglBase eglBase = this.mEglBase;
        if (eglBase == null) {
            return 0;
        }
        return eglBase.surfaceWidth();
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public int surfaceHeight() {
        EglBase eglBase = this.mEglBase;
        if (eglBase == null) {
            return 0;
        }
        return eglBase.surfaceHeight();
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void releaseSurface() {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.releaseSurface();
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void makeCurrent() {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.makeCurrent();
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void detachCurrent() {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.detachCurrent();
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void swapBuffers() {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.swapBuffers();
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void swapBuffers(long presentationTimeStampNs) {
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.swapBuffers(presentationTimeStampNs);
        }
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public EglBase getEglBase() {
        return this.mEglBase;
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void setTraceId(String name) {
        this.name = name;
        EglBase eglBase = this.mEglBase;
        if (eglBase != null) {
            eglBase.setTraceId(name);
        }
    }
}
