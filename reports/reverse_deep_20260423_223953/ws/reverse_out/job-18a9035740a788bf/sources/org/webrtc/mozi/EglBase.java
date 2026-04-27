package org.webrtc.mozi;

import android.graphics.SurfaceTexture;
import android.view.Surface;
import javax.annotation.Nullable;
import javax.microedition.khronos.egl.EGLContext;
import org.webrtc.mozi.EglBase10;
import org.webrtc.mozi.EglBase14;

/* JADX INFO: loaded from: classes3.dex */
public abstract class EglBase {
    public static final int EGL_OPENGL_ES2_BIT = 4;
    public static final Object lock = new Object();
    public static final int[] CONFIG_PLAIN = {12324, 8, 12323, 8, 12322, 8, 12352, 4, 12344};
    public static final int[] CONFIG_RGBA = {12324, 8, 12323, 8, 12322, 8, 12321, 8, 12352, 4, 12344};
    public static final int[] CONFIG_PIXEL_BUFFER = {12324, 8, 12323, 8, 12322, 8, 12352, 4, 12339, 1, 12344};
    public static final int[] CONFIG_PIXEL_RGBA_BUFFER = {12324, 8, 12323, 8, 12322, 8, 12321, 8, 12352, 4, 12339, 1, 12344};
    public static final int EGL_RECORDABLE_ANDROID = 12610;
    public static final int[] CONFIG_RECORDABLE = {12324, 8, 12323, 8, 12322, 8, 12352, 4, EGL_RECORDABLE_ANDROID, 1, 12344};
    public static final int[] CONFIG_RGBA_TRANSLUCENT = {12324, 8, 12323, 8, 12322, 8, 12321, 8, 12325, 16, 12326, 0, 12344};

    public interface Context {
        long getNativeEglContext();
    }

    public abstract void createDummyPbufferSurface();

    public abstract void createPbufferSurface(int i, int i2);

    public abstract void createSurface(SurfaceTexture surfaceTexture);

    public abstract void createSurface(Surface surface);

    public abstract void detachCurrent();

    public abstract Context getEglBaseContext();

    public abstract boolean hasSurface();

    public abstract void makeCurrent();

    public abstract void release();

    public abstract void releaseSurface();

    public abstract void setTraceId(String str);

    public abstract int surfaceHeight();

    public abstract int surfaceWidth();

    public abstract void swapBuffers();

    public abstract void swapBuffers(long j);

    public static EglBase create(@Nullable Context sharedContext, int[] configAttributes) {
        return (EglBase14.isEGL14Supported() && (sharedContext == null || (sharedContext instanceof EglBase14.Context))) ? new EglBase14((EglBase14.Context) sharedContext, configAttributes) : new EglBase10((EglBase10.Context) sharedContext, configAttributes);
    }

    public static EglBase create() {
        return create(null, CONFIG_PLAIN);
    }

    long getSharedContext() {
        return 0L;
    }

    public static EglBase create(Context sharedContext) {
        return create(sharedContext, CONFIG_PLAIN);
    }

    public static EglBase createEgl10(int[] configAttributes) {
        return new EglBase10(null, configAttributes);
    }

    public static EglBase createEgl10(EGLContext sharedContext, int[] configAttributes) {
        return new EglBase10(new EglBase10.Context(sharedContext), configAttributes);
    }

    public static EglBase createEgl14(int[] configAttributes) {
        return new EglBase14(null, configAttributes);
    }

    public static EglBase createEgl14(android.opengl.EGLContext sharedContext, int[] configAttributes) {
        return new EglBase14(new EglBase14.Context(sharedContext), configAttributes);
    }
}
