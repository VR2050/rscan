package com.google.android.exoplayer2.p395ui.spherical;

import android.content.Context;
import android.graphics.SurfaceTexture;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.opengl.GLES20;
import android.opengl.GLSurfaceView;
import android.opengl.Matrix;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.Surface;
import android.view.WindowManager;
import androidx.annotation.AnyThread;
import androidx.annotation.BinderThread;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.google.android.exoplayer2.p395ui.spherical.SphericalGLSurfaceView;
import java.nio.Buffer;
import java.util.Objects;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;
import p005b.p199l.p200a.p201a.C2392r0;
import p005b.p199l.p200a.p201a.C2402w0;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.InterfaceC2396t0;
import p005b.p199l.p200a.p201a.p246n1.p247h.C2273d;
import p005b.p199l.p200a.p201a.p246n1.p247h.C2274e;
import p005b.p199l.p200a.p201a.p246n1.p247h.C2275f;
import p005b.p199l.p200a.p201a.p246n1.p247h.InterfaceC2276g;
import p005b.p199l.p200a.p201a.p246n1.p247h.ViewOnTouchListenerC2277h;
import p005b.p199l.p200a.p201a.p250p1.C2340b0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p251q1.p252s.C2389c;
import p005b.p199l.p200a.p201a.p251q1.p252s.C2390d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class SphericalGLSurfaceView extends GLSurfaceView {

    /* renamed from: c */
    public final SensorManager f9718c;

    /* renamed from: e */
    @Nullable
    public final Sensor f9719e;

    /* renamed from: f */
    public final C2273d f9720f;

    /* renamed from: g */
    public final Handler f9721g;

    /* renamed from: h */
    public final ViewOnTouchListenerC2277h f9722h;

    /* renamed from: i */
    public final C2275f f9723i;

    /* renamed from: j */
    @Nullable
    public SurfaceTexture f9724j;

    /* renamed from: k */
    @Nullable
    public Surface f9725k;

    /* renamed from: l */
    @Nullable
    public InterfaceC2368q0.c f9726l;

    @VisibleForTesting
    /* renamed from: com.google.android.exoplayer2.ui.spherical.SphericalGLSurfaceView$a */
    public class C3324a implements GLSurfaceView.Renderer, ViewOnTouchListenerC2277h.a, C2273d.a {

        /* renamed from: c */
        public final C2275f f9727c;

        /* renamed from: g */
        public final float[] f9730g;

        /* renamed from: h */
        public final float[] f9731h;

        /* renamed from: i */
        public final float[] f9732i;

        /* renamed from: j */
        public float f9733j;

        /* renamed from: k */
        public float f9734k;

        /* renamed from: e */
        public final float[] f9728e = new float[16];

        /* renamed from: f */
        public final float[] f9729f = new float[16];

        /* renamed from: l */
        public final float[] f9735l = new float[16];

        /* renamed from: m */
        public final float[] f9736m = new float[16];

        public C3324a(C2275f c2275f) {
            float[] fArr = new float[16];
            this.f9730g = fArr;
            float[] fArr2 = new float[16];
            this.f9731h = fArr2;
            float[] fArr3 = new float[16];
            this.f9732i = fArr3;
            this.f9727c = c2275f;
            Matrix.setIdentityM(fArr, 0);
            Matrix.setIdentityM(fArr2, 0);
            Matrix.setIdentityM(fArr3, 0);
            this.f9734k = 3.1415927f;
        }

        @Override // p005b.p199l.p200a.p201a.p246n1.p247h.C2273d.a
        @BinderThread
        /* renamed from: a */
        public synchronized void mo2172a(float[] fArr, float f2) {
            float[] fArr2 = this.f9730g;
            System.arraycopy(fArr, 0, fArr2, 0, fArr2.length);
            this.f9734k = -f2;
            m4127b();
        }

        @AnyThread
        /* renamed from: b */
        public final void m4127b() {
            Matrix.setRotateM(this.f9731h, 0, -this.f9733j, (float) Math.cos(this.f9734k), (float) Math.sin(this.f9734k), 0.0f);
        }

        @Override // android.opengl.GLSurfaceView.Renderer
        public void onDrawFrame(GL10 gl10) {
            Long m2303d;
            float[] fArr;
            synchronized (this) {
                Matrix.multiplyMM(this.f9736m, 0, this.f9730g, 0, this.f9732i, 0);
                Matrix.multiplyMM(this.f9735l, 0, this.f9731h, 0, this.f9736m, 0);
            }
            Matrix.multiplyMM(this.f9729f, 0, this.f9728e, 0, this.f9735l, 0);
            C2275f c2275f = this.f9727c;
            float[] fArr2 = this.f9729f;
            Objects.requireNonNull(c2275f);
            GLES20.glClear(16384);
            C2354n.m2527x();
            if (c2275f.f5744a.compareAndSet(true, false)) {
                SurfaceTexture surfaceTexture = c2275f.f5753j;
                Objects.requireNonNull(surfaceTexture);
                surfaceTexture.updateTexImage();
                C2354n.m2527x();
                if (c2275f.f5745b.compareAndSet(true, false)) {
                    Matrix.setIdentityM(c2275f.f5750g, 0);
                }
                long timestamp = c2275f.f5753j.getTimestamp();
                C2340b0<Long> c2340b0 = c2275f.f5748e;
                synchronized (c2340b0) {
                    m2303d = c2340b0.m2303d(timestamp, false);
                }
                Long l2 = m2303d;
                if (l2 != null) {
                    C2389c c2389c = c2275f.f5747d;
                    float[] fArr3 = c2275f.f5750g;
                    float[] m2304e = c2389c.f6277c.m2304e(l2.longValue());
                    if (m2304e != null) {
                        float[] fArr4 = c2389c.f6276b;
                        float f2 = m2304e[0];
                        float f3 = -m2304e[1];
                        float f4 = -m2304e[2];
                        float length = Matrix.length(f2, f3, f4);
                        if (length != 0.0f) {
                            fArr = fArr3;
                            Matrix.setRotateM(fArr4, 0, (float) Math.toDegrees(length), f2 / length, f3 / length, f4 / length);
                        } else {
                            fArr = fArr3;
                            Matrix.setIdentityM(fArr4, 0);
                        }
                        if (!c2389c.f6278d) {
                            C2389c.m2643a(c2389c.f6275a, c2389c.f6276b);
                            c2389c.f6278d = true;
                        }
                        Matrix.multiplyMM(fArr, 0, c2389c.f6275a, 0, c2389c.f6276b, 0);
                    }
                }
                C2390d m2304e2 = c2275f.f5749f.m2304e(timestamp);
                if (m2304e2 != null) {
                    C2274e c2274e = c2275f.f5746c;
                    Objects.requireNonNull(c2274e);
                    if (C2274e.m2173a(m2304e2)) {
                        c2274e.f5731h = m2304e2.f6281c;
                        C2274e.a aVar = new C2274e.a(m2304e2.f6279a.f6283a[0]);
                        c2274e.f5732i = aVar;
                        if (!m2304e2.f6282d) {
                            aVar = new C2274e.a(m2304e2.f6280b.f6283a[0]);
                        }
                        c2274e.f5733j = aVar;
                    }
                }
            }
            Matrix.multiplyMM(c2275f.f5751h, 0, fArr2, 0, c2275f.f5750g, 0);
            C2274e c2274e2 = c2275f.f5746c;
            int i2 = c2275f.f5752i;
            float[] fArr5 = c2275f.f5751h;
            C2274e.a aVar2 = c2274e2.f5732i;
            if (aVar2 == null) {
                return;
            }
            GLES20.glUseProgram(c2274e2.f5734k);
            C2354n.m2527x();
            GLES20.glEnableVertexAttribArray(c2274e2.f5737n);
            GLES20.glEnableVertexAttribArray(c2274e2.f5738o);
            C2354n.m2527x();
            int i3 = c2274e2.f5731h;
            GLES20.glUniformMatrix3fv(c2274e2.f5736m, 1, false, i3 == 1 ? C2274e.f5727d : i3 == 2 ? C2274e.f5729f : C2274e.f5726c, 0);
            GLES20.glUniformMatrix4fv(c2274e2.f5735l, 1, false, fArr5, 0);
            GLES20.glActiveTexture(33984);
            GLES20.glBindTexture(36197, i2);
            GLES20.glUniform1i(c2274e2.f5739p, 0);
            C2354n.m2527x();
            GLES20.glVertexAttribPointer(c2274e2.f5737n, 3, 5126, false, 12, (Buffer) aVar2.f5741b);
            C2354n.m2527x();
            GLES20.glVertexAttribPointer(c2274e2.f5738o, 2, 5126, false, 8, (Buffer) aVar2.f5742c);
            C2354n.m2527x();
            GLES20.glDrawArrays(aVar2.f5743d, 0, aVar2.f5740a);
            C2354n.m2527x();
            GLES20.glDisableVertexAttribArray(c2274e2.f5737n);
            GLES20.glDisableVertexAttribArray(c2274e2.f5738o);
        }

        @Override // android.opengl.GLSurfaceView.Renderer
        public void onSurfaceChanged(GL10 gl10, int i2, int i3) {
            GLES20.glViewport(0, 0, i2, i3);
            float f2 = i2 / i3;
            Matrix.perspectiveM(this.f9728e, 0, f2 > 1.0f ? (float) (Math.toDegrees(Math.atan(Math.tan(Math.toRadians(45.0d)) / f2)) * 2.0d) : 90.0f, f2, 0.1f, 100.0f);
        }

        @Override // android.opengl.GLSurfaceView.Renderer
        public synchronized void onSurfaceCreated(GL10 gl10, EGLConfig eGLConfig) {
            final SphericalGLSurfaceView sphericalGLSurfaceView = SphericalGLSurfaceView.this;
            final SurfaceTexture m2177d = this.f9727c.m2177d();
            sphericalGLSurfaceView.f9721g.post(new Runnable() { // from class: b.l.a.a.n1.h.c
                @Override // java.lang.Runnable
                public final void run() {
                    SphericalGLSurfaceView sphericalGLSurfaceView2 = SphericalGLSurfaceView.this;
                    SurfaceTexture surfaceTexture = m2177d;
                    SurfaceTexture surfaceTexture2 = sphericalGLSurfaceView2.f9724j;
                    Surface surface = sphericalGLSurfaceView2.f9725k;
                    sphericalGLSurfaceView2.f9724j = surfaceTexture;
                    Surface surface2 = new Surface(surfaceTexture);
                    sphericalGLSurfaceView2.f9725k = surface2;
                    InterfaceC2368q0.c cVar = sphericalGLSurfaceView2.f9726l;
                    if (cVar != null) {
                        ((C2402w0) cVar).m2678O(surface2);
                    }
                    if (surfaceTexture2 != null) {
                        surfaceTexture2.release();
                    }
                    if (surface != null) {
                        surface.release();
                    }
                }
            });
        }
    }

    public SphericalGLSurfaceView(Context context) {
        this(context, null);
    }

    @Override // android.opengl.GLSurfaceView, android.view.SurfaceView, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f9721g.post(new Runnable() { // from class: b.l.a.a.n1.h.b
            @Override // java.lang.Runnable
            public final void run() {
                SphericalGLSurfaceView sphericalGLSurfaceView = SphericalGLSurfaceView.this;
                Surface surface = sphericalGLSurfaceView.f9725k;
                if (surface != null) {
                    InterfaceC2368q0.c cVar = sphericalGLSurfaceView.f9726l;
                    if (cVar != null) {
                        ((C2402w0) cVar).m2671H(surface);
                    }
                    SurfaceTexture surfaceTexture = sphericalGLSurfaceView.f9724j;
                    Surface surface2 = sphericalGLSurfaceView.f9725k;
                    if (surfaceTexture != null) {
                        surfaceTexture.release();
                    }
                    if (surface2 != null) {
                        surface2.release();
                    }
                    sphericalGLSurfaceView.f9724j = null;
                    sphericalGLSurfaceView.f9725k = null;
                }
            }
        });
    }

    @Override // android.opengl.GLSurfaceView
    public void onPause() {
        if (this.f9719e != null) {
            this.f9718c.unregisterListener(this.f9720f);
        }
        super.onPause();
    }

    @Override // android.opengl.GLSurfaceView
    public void onResume() {
        super.onResume();
        Sensor sensor = this.f9719e;
        if (sensor != null) {
            this.f9718c.registerListener(this.f9720f, sensor, 0);
        }
    }

    public void setDefaultStereoMode(int i2) {
        this.f9723i.f5754k = i2;
    }

    public void setSingleTapListener(@Nullable InterfaceC2276g interfaceC2276g) {
        this.f9722h.f5763j = interfaceC2276g;
    }

    public void setVideoComponent(@Nullable InterfaceC2368q0.c cVar) {
        InterfaceC2368q0.c cVar2 = this.f9726l;
        if (cVar == cVar2) {
            return;
        }
        if (cVar2 != null) {
            Surface surface = this.f9725k;
            if (surface != null) {
                ((C2402w0) cVar2).m2671H(surface);
            }
            InterfaceC2368q0.c cVar3 = this.f9726l;
            C2275f c2275f = this.f9723i;
            C2402w0 c2402w0 = (C2402w0) cVar3;
            c2402w0.m2684U();
            if (c2402w0.f6336A == c2275f) {
                for (InterfaceC2396t0 interfaceC2396t0 : c2402w0.f6340b) {
                    if (interfaceC2396t0.getTrackType() == 2) {
                        C2392r0 m1345G = c2402w0.f6341c.m1345G(interfaceC2396t0);
                        m1345G.m2648e(6);
                        m1345G.m2647d(null);
                        m1345G.m2646c();
                    }
                }
            }
            InterfaceC2368q0.c cVar4 = this.f9726l;
            C2275f c2275f2 = this.f9723i;
            C2402w0 c2402w02 = (C2402w0) cVar4;
            c2402w02.m2684U();
            if (c2402w02.f6337B == c2275f2) {
                for (InterfaceC2396t0 interfaceC2396t02 : c2402w02.f6340b) {
                    if (interfaceC2396t02.getTrackType() == 5) {
                        C2392r0 m1345G2 = c2402w02.f6341c.m1345G(interfaceC2396t02);
                        m1345G2.m2648e(7);
                        m1345G2.m2647d(null);
                        m1345G2.m2646c();
                    }
                }
            }
        }
        this.f9726l = cVar;
        if (cVar != null) {
            C2275f c2275f3 = this.f9723i;
            C2402w0 c2402w03 = (C2402w0) cVar;
            c2402w03.m2684U();
            c2402w03.f6336A = c2275f3;
            for (InterfaceC2396t0 interfaceC2396t03 : c2402w03.f6340b) {
                if (interfaceC2396t03.getTrackType() == 2) {
                    C2392r0 m1345G3 = c2402w03.f6341c.m1345G(interfaceC2396t03);
                    m1345G3.m2648e(6);
                    C4195m.m4771I(!m1345G3.f6301h);
                    m1345G3.f6298e = c2275f3;
                    m1345G3.m2646c();
                }
            }
            InterfaceC2368q0.c cVar5 = this.f9726l;
            C2275f c2275f4 = this.f9723i;
            C2402w0 c2402w04 = (C2402w0) cVar5;
            c2402w04.m2684U();
            c2402w04.f6337B = c2275f4;
            for (InterfaceC2396t0 interfaceC2396t04 : c2402w04.f6340b) {
                if (interfaceC2396t04.getTrackType() == 5) {
                    C2392r0 m1345G4 = c2402w04.f6341c.m1345G(interfaceC2396t04);
                    m1345G4.m2648e(7);
                    C4195m.m4771I(!m1345G4.f6301h);
                    m1345G4.f6298e = c2275f4;
                    m1345G4.m2646c();
                }
            }
            ((C2402w0) this.f9726l).m2678O(this.f9725k);
        }
    }

    public SphericalGLSurfaceView(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f9721g = new Handler(Looper.getMainLooper());
        Object systemService = context.getSystemService("sensor");
        Objects.requireNonNull(systemService);
        SensorManager sensorManager = (SensorManager) systemService;
        this.f9718c = sensorManager;
        Sensor defaultSensor = C2344d0.f6035a >= 18 ? sensorManager.getDefaultSensor(15) : null;
        this.f9719e = defaultSensor == null ? sensorManager.getDefaultSensor(11) : defaultSensor;
        C2275f c2275f = new C2275f();
        this.f9723i = c2275f;
        C3324a c3324a = new C3324a(c2275f);
        ViewOnTouchListenerC2277h viewOnTouchListenerC2277h = new ViewOnTouchListenerC2277h(context, c3324a, 25.0f);
        this.f9722h = viewOnTouchListenerC2277h;
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        Objects.requireNonNull(windowManager);
        this.f9720f = new C2273d(windowManager.getDefaultDisplay(), viewOnTouchListenerC2277h, c3324a);
        setEGLContextClientVersion(2);
        setRenderer(c3324a);
        setOnTouchListener(viewOnTouchListenerC2277h);
    }
}
