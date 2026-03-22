package p005b.p362y.p363a.p369i.p371c;

import android.annotation.SuppressLint;
import android.graphics.SurfaceTexture;
import android.opengl.GLES20;
import android.opengl.GLSurfaceView;
import android.os.Handler;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import java.util.Objects;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2945a;
import p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2946b;

@SuppressLint({"ViewConstructor"})
/* renamed from: b.y.a.i.c.b */
/* loaded from: classes2.dex */
public abstract class AbstractC2942b implements GLSurfaceView.Renderer, SurfaceTexture.OnFrameAvailableListener {

    /* renamed from: e */
    public InterfaceC2945a f8050e;

    /* renamed from: f */
    public GLSurfaceView f8051f;

    /* renamed from: m */
    public InterfaceC2946b f8058m;

    /* renamed from: c */
    public boolean f8049c = false;

    /* renamed from: g */
    public float[] f8052g = new float[16];

    /* renamed from: h */
    public float[] f8053h = new float[16];

    /* renamed from: i */
    public int f8054i = 0;

    /* renamed from: j */
    public int f8055j = 0;

    /* renamed from: k */
    public boolean f8056k = false;

    /* renamed from: l */
    public boolean f8057l = false;

    /* renamed from: n */
    public Handler f8059n = new Handler();

    /* renamed from: b.y.a.i.c.b$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ String f8060c;

        /* renamed from: e */
        public final /* synthetic */ int f8061e;

        public a(String str, int i2) {
            this.f8060c = str;
            this.f8061e = i2;
        }

        @Override // java.lang.Runnable
        public void run() {
            AbstractC2942b abstractC2942b = AbstractC2942b.this;
            InterfaceC2946b interfaceC2946b = abstractC2942b.f8058m;
            if (interfaceC2946b != null) {
                boolean z = abstractC2942b.f8057l;
                GSYVideoGLView.C4090b c4090b = (GSYVideoGLView.C4090b) interfaceC2946b;
                Objects.requireNonNull(c4090b);
                if (z) {
                    GSYVideoGLView.m4635e(c4090b.f10783a, c4090b.f10784b, c4090b.f10785c, c4090b.f10786d, c4090b.f10787e, ((C2943c) abstractC2942b).f8063A, abstractC2942b.f8052g, abstractC2942b, c4090b.f10788f);
                }
            }
            AbstractC2942b.this.f8057l = false;
        }
    }

    /* renamed from: a */
    public void m3405a(String str) {
        int glGetError = GLES20.glGetError();
        if (glGetError != 0) {
            Debuger.printfError(str + ": glError " + glGetError);
            this.f8059n.post(new a(str, glGetError));
        }
    }

    /* renamed from: b */
    public int m3406b(String str, String str2) {
        int m3407c;
        int m3407c2 = m3407c(35633, str);
        if (m3407c2 == 0 || (m3407c = m3407c(35632, str2)) == 0) {
            return 0;
        }
        int glCreateProgram = GLES20.glCreateProgram();
        if (glCreateProgram != 0) {
            GLES20.glAttachShader(glCreateProgram, m3407c2);
            m3405a("glAttachShader");
            GLES20.glAttachShader(glCreateProgram, m3407c);
            m3405a("glAttachShader");
            GLES20.glLinkProgram(glCreateProgram);
            int[] iArr = new int[1];
            GLES20.glGetProgramiv(glCreateProgram, 35714, iArr, 0);
            if (iArr[0] != 1) {
                Debuger.printfError("Could not link program: ");
                Debuger.printfError(GLES20.glGetProgramInfoLog(glCreateProgram));
                GLES20.glDeleteProgram(glCreateProgram);
                return 0;
            }
        }
        return glCreateProgram;
    }

    /* renamed from: c */
    public int m3407c(int i2, String str) {
        int glCreateShader = GLES20.glCreateShader(i2);
        if (glCreateShader == 0) {
            return glCreateShader;
        }
        GLES20.glShaderSource(glCreateShader, str);
        GLES20.glCompileShader(glCreateShader);
        int[] iArr = new int[1];
        GLES20.glGetShaderiv(glCreateShader, 35713, iArr, 0);
        if (iArr[0] != 0) {
            return glCreateShader;
        }
        Debuger.printfError("Could not compile shader " + i2 + ":");
        Debuger.printfError(GLES20.glGetShaderInfoLog(glCreateShader));
        GLES20.glDeleteShader(glCreateShader);
        return 0;
    }
}
