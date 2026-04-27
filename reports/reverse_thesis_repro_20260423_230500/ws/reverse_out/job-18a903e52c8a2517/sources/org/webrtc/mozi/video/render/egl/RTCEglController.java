package org.webrtc.mozi.video.render.egl;

import android.graphics.SurfaceTexture;
import android.os.Handler;
import android.view.Surface;
import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public interface RTCEglController {
    public static final int SURFACE_SIZE_DEFAULT = 0;

    void createSurface(SurfaceTexture surfaceTexture);

    void createSurface(Surface surface);

    void detachCurrent();

    EglBase getEglBase();

    Handler getRenderHandler(String str);

    boolean hasSurface();

    void makeCurrent();

    void release();

    void releaseSurface();

    void setTraceId(String str);

    int surfaceHeight();

    int surfaceWidth();

    void swapBuffers();

    void swapBuffers(long j);
}
