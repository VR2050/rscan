package com.google.android.exoplayer2.video;

import android.annotation.TargetApi;
import android.content.Context;
import android.graphics.SurfaceTexture;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.view.Surface;
import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p250p1.RunnableC2350j;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@TargetApi(17)
/* loaded from: classes.dex */
public final class DummySurface extends Surface {

    /* renamed from: c */
    public static int f9749c;

    /* renamed from: e */
    public static boolean f9750e;

    /* renamed from: f */
    public final HandlerThreadC3328b f9751f;

    /* renamed from: g */
    public boolean f9752g;

    /* renamed from: com.google.android.exoplayer2.video.DummySurface$b */
    public static class HandlerThreadC3328b extends HandlerThread implements Handler.Callback {

        /* renamed from: c */
        public RunnableC2350j f9753c;

        /* renamed from: e */
        public Handler f9754e;

        /* renamed from: f */
        @Nullable
        public Error f9755f;

        /* renamed from: g */
        @Nullable
        public RuntimeException f9756g;

        /* renamed from: h */
        @Nullable
        public DummySurface f9757h;

        public HandlerThreadC3328b() {
            super("dummySurface");
        }

        /* renamed from: a */
        public final void m4131a(int i2) {
            EGLSurface eglCreatePbufferSurface;
            Objects.requireNonNull(this.f9753c);
            RunnableC2350j runnableC2350j = this.f9753c;
            Objects.requireNonNull(runnableC2350j);
            EGLDisplay eglGetDisplay = EGL14.eglGetDisplay(0);
            if (eglGetDisplay == null) {
                throw new RunnableC2350j.b("eglGetDisplay failed", null);
            }
            int[] iArr = new int[2];
            if (!EGL14.eglInitialize(eglGetDisplay, iArr, 0, iArr, 1)) {
                throw new RunnableC2350j.b("eglInitialize failed", null);
            }
            runnableC2350j.f6065g = eglGetDisplay;
            EGLConfig[] eGLConfigArr = new EGLConfig[1];
            int[] iArr2 = new int[1];
            boolean eglChooseConfig = EGL14.eglChooseConfig(eglGetDisplay, RunnableC2350j.f6062c, 0, eGLConfigArr, 0, 1, iArr2, 0);
            if (!eglChooseConfig || iArr2[0] <= 0 || eGLConfigArr[0] == null) {
                throw new RunnableC2350j.b(C2344d0.m2332j("eglChooseConfig failed: success=%b, numConfigs[0]=%d, configs[0]=%s", Boolean.valueOf(eglChooseConfig), Integer.valueOf(iArr2[0]), eGLConfigArr[0]), null);
            }
            EGLConfig eGLConfig = eGLConfigArr[0];
            EGLContext eglCreateContext = EGL14.eglCreateContext(runnableC2350j.f6065g, eGLConfig, EGL14.EGL_NO_CONTEXT, i2 == 0 ? new int[]{12440, 2, 12344} : new int[]{12440, 2, 12992, 1, 12344}, 0);
            if (eglCreateContext == null) {
                throw new RunnableC2350j.b("eglCreateContext failed", null);
            }
            runnableC2350j.f6066h = eglCreateContext;
            EGLDisplay eGLDisplay = runnableC2350j.f6065g;
            if (i2 == 1) {
                eglCreatePbufferSurface = EGL14.EGL_NO_SURFACE;
            } else {
                eglCreatePbufferSurface = EGL14.eglCreatePbufferSurface(eGLDisplay, eGLConfig, i2 == 2 ? new int[]{12375, 1, 12374, 1, 12992, 1, 12344} : new int[]{12375, 1, 12374, 1, 12344}, 0);
                if (eglCreatePbufferSurface == null) {
                    throw new RunnableC2350j.b("eglCreatePbufferSurface failed", null);
                }
            }
            if (!EGL14.eglMakeCurrent(eGLDisplay, eglCreatePbufferSurface, eglCreatePbufferSurface, eglCreateContext)) {
                throw new RunnableC2350j.b("eglMakeCurrent failed", null);
            }
            runnableC2350j.f6067i = eglCreatePbufferSurface;
            GLES20.glGenTextures(1, runnableC2350j.f6064f, 0);
            C2354n.m2527x();
            SurfaceTexture surfaceTexture = new SurfaceTexture(runnableC2350j.f6064f[0]);
            runnableC2350j.f6068j = surfaceTexture;
            surfaceTexture.setOnFrameAvailableListener(runnableC2350j);
            SurfaceTexture surfaceTexture2 = this.f9753c.f6068j;
            Objects.requireNonNull(surfaceTexture2);
            this.f9757h = new DummySurface(this, surfaceTexture2, i2 != 0, null);
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* renamed from: b */
        public final void m4132b() {
            Objects.requireNonNull(this.f9753c);
            RunnableC2350j runnableC2350j = this.f9753c;
            runnableC2350j.f6063e.removeCallbacks(runnableC2350j);
            try {
                SurfaceTexture surfaceTexture = runnableC2350j.f6068j;
                if (surfaceTexture != null) {
                    surfaceTexture.release();
                    GLES20.glDeleteTextures(1, runnableC2350j.f6064f, 0);
                }
            } finally {
                EGLDisplay eGLDisplay = runnableC2350j.f6065g;
                if (eGLDisplay != null && !eGLDisplay.equals(EGL14.EGL_NO_DISPLAY)) {
                    EGLDisplay eGLDisplay2 = runnableC2350j.f6065g;
                    EGLSurface eGLSurface = EGL14.EGL_NO_SURFACE;
                    EGL14.eglMakeCurrent(eGLDisplay2, eGLSurface, eGLSurface, EGL14.EGL_NO_CONTEXT);
                }
                EGLSurface eGLSurface2 = runnableC2350j.f6067i;
                if (eGLSurface2 != null && !eGLSurface2.equals(EGL14.EGL_NO_SURFACE)) {
                    EGL14.eglDestroySurface(runnableC2350j.f6065g, runnableC2350j.f6067i);
                }
                EGLContext eGLContext = runnableC2350j.f6066h;
                if (eGLContext != null) {
                    EGL14.eglDestroyContext(runnableC2350j.f6065g, eGLContext);
                }
                if (C2344d0.f6035a >= 19) {
                    EGL14.eglReleaseThread();
                }
                EGLDisplay eGLDisplay3 = runnableC2350j.f6065g;
                if (eGLDisplay3 != null && !eGLDisplay3.equals(EGL14.EGL_NO_DISPLAY)) {
                    EGL14.eglTerminate(runnableC2350j.f6065g);
                }
                runnableC2350j.f6065g = null;
                runnableC2350j.f6066h = null;
                runnableC2350j.f6067i = null;
                runnableC2350j.f6068j = null;
            }
        }

        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message message) {
            int i2 = message.what;
            try {
                if (i2 != 1) {
                    if (i2 != 2) {
                        return true;
                    }
                    try {
                        m4132b();
                    } catch (Throwable unused) {
                    }
                    quit();
                    return true;
                }
                try {
                    m4131a(message.arg1);
                    synchronized (this) {
                        notify();
                    }
                } catch (Error e2) {
                    this.f9755f = e2;
                    synchronized (this) {
                        notify();
                    }
                } catch (RuntimeException e3) {
                    this.f9756g = e3;
                    synchronized (this) {
                        notify();
                    }
                }
                return true;
            } catch (Throwable th) {
                synchronized (this) {
                    notify();
                    throw th;
                }
            }
        }
    }

    public DummySurface(HandlerThreadC3328b handlerThreadC3328b, SurfaceTexture surfaceTexture, boolean z, C3327a c3327a) {
        super(surfaceTexture);
        this.f9751f = handlerThreadC3328b;
    }

    /* renamed from: b */
    public static int m4128b(Context context) {
        String eglQueryString;
        String eglQueryString2;
        int i2 = C2344d0.f6035a;
        boolean z = false;
        if (!(i2 >= 24 && (i2 >= 26 || !("samsung".equals(C2344d0.f6037c) || "XT1650".equals(C2344d0.f6038d))) && ((i2 >= 26 || context.getPackageManager().hasSystemFeature("android.hardware.vr.high_performance")) && (eglQueryString2 = EGL14.eglQueryString(EGL14.eglGetDisplay(0), 12373)) != null && eglQueryString2.contains("EGL_EXT_protected_content")))) {
            return 0;
        }
        if (i2 >= 17 && (eglQueryString = EGL14.eglQueryString(EGL14.eglGetDisplay(0), 12373)) != null && eglQueryString.contains("EGL_KHR_surfaceless_context")) {
            z = true;
        }
        return z ? 1 : 2;
    }

    /* renamed from: e */
    public static synchronized boolean m4129e(Context context) {
        boolean z;
        synchronized (DummySurface.class) {
            if (!f9750e) {
                f9749c = m4128b(context);
                f9750e = true;
            }
            z = f9749c != 0;
        }
        return z;
    }

    /* renamed from: k */
    public static DummySurface m4130k(Context context, boolean z) {
        if (C2344d0.f6035a < 17) {
            throw new UnsupportedOperationException("Unsupported prior to API level 17");
        }
        boolean z2 = false;
        C4195m.m4771I(!z || m4129e(context));
        HandlerThreadC3328b handlerThreadC3328b = new HandlerThreadC3328b();
        int i2 = z ? f9749c : 0;
        handlerThreadC3328b.start();
        Handler handler = new Handler(handlerThreadC3328b.getLooper(), handlerThreadC3328b);
        handlerThreadC3328b.f9754e = handler;
        handlerThreadC3328b.f9753c = new RunnableC2350j(handler);
        synchronized (handlerThreadC3328b) {
            handlerThreadC3328b.f9754e.obtainMessage(1, i2, 0).sendToTarget();
            while (handlerThreadC3328b.f9757h == null && handlerThreadC3328b.f9756g == null && handlerThreadC3328b.f9755f == null) {
                try {
                    handlerThreadC3328b.wait();
                } catch (InterruptedException unused) {
                    z2 = true;
                }
            }
        }
        if (z2) {
            Thread.currentThread().interrupt();
        }
        RuntimeException runtimeException = handlerThreadC3328b.f9756g;
        if (runtimeException != null) {
            throw runtimeException;
        }
        Error error = handlerThreadC3328b.f9755f;
        if (error != null) {
            throw error;
        }
        DummySurface dummySurface = handlerThreadC3328b.f9757h;
        Objects.requireNonNull(dummySurface);
        return dummySurface;
    }

    @Override // android.view.Surface
    public void release() {
        super.release();
        synchronized (this.f9751f) {
            if (!this.f9752g) {
                HandlerThreadC3328b handlerThreadC3328b = this.f9751f;
                Objects.requireNonNull(handlerThreadC3328b.f9754e);
                handlerThreadC3328b.f9754e.sendEmptyMessage(2);
                this.f9752g = true;
            }
        }
    }
}
