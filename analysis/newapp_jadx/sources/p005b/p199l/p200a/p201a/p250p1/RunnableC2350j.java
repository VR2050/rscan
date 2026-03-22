package p005b.p199l.p200a.p201a.p250p1;

import android.annotation.TargetApi;
import android.graphics.SurfaceTexture;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.os.Handler;
import androidx.annotation.Nullable;

@TargetApi(17)
/* renamed from: b.l.a.a.p1.j */
/* loaded from: classes.dex */
public final class RunnableC2350j implements SurfaceTexture.OnFrameAvailableListener, Runnable {

    /* renamed from: c */
    public static final int[] f6062c = {12352, 4, 12324, 8, 12323, 8, 12322, 8, 12321, 8, 12325, 0, 12327, 12344, 12339, 4, 12344};

    /* renamed from: e */
    public final Handler f6063e;

    /* renamed from: f */
    public final int[] f6064f = new int[1];

    /* renamed from: g */
    @Nullable
    public EGLDisplay f6065g;

    /* renamed from: h */
    @Nullable
    public EGLContext f6066h;

    /* renamed from: i */
    @Nullable
    public EGLSurface f6067i;

    /* renamed from: j */
    @Nullable
    public SurfaceTexture f6068j;

    /* renamed from: b.l.a.a.p1.j$b */
    public static final class b extends RuntimeException {
        public b(String str, a aVar) {
            super(str);
        }
    }

    public RunnableC2350j(Handler handler) {
        this.f6063e = handler;
    }

    @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
    public void onFrameAvailable(SurfaceTexture surfaceTexture) {
        this.f6063e.post(this);
    }

    @Override // java.lang.Runnable
    public void run() {
        SurfaceTexture surfaceTexture = this.f6068j;
        if (surfaceTexture != null) {
            try {
                surfaceTexture.updateTexImage();
            } catch (RuntimeException unused) {
            }
        }
    }
}
