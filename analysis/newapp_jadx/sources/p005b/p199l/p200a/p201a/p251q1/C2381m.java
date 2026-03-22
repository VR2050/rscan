package p005b.p199l.p200a.p201a.p251q1;

import android.opengl.GLES20;
import android.opengl.GLSurfaceView;
import androidx.annotation.Nullable;
import androidx.work.Data;
import com.google.android.exoplayer2.video.VideoDecoderOutputBuffer;
import java.nio.Buffer;
import java.nio.FloatBuffer;
import java.util.concurrent.atomic.AtomicReference;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.q1.m */
/* loaded from: classes.dex */
public class C2381m implements GLSurfaceView.Renderer, InterfaceC2380l {

    /* renamed from: c */
    public static final float[] f6234c = {1.164f, 1.164f, 1.164f, 0.0f, -0.392f, 2.017f, 1.596f, -0.813f, 0.0f};

    /* renamed from: e */
    public static final float[] f6235e = {1.164f, 1.164f, 1.164f, 0.0f, -0.213f, 2.112f, 1.793f, -0.533f, 0.0f};

    /* renamed from: f */
    public static final float[] f6236f = {1.168f, 1.168f, 1.168f, 0.0f, -0.188f, 2.148f, 1.683f, -0.652f, 0.0f};

    /* renamed from: g */
    public static final String[] f6237g = {"y_tex", "u_tex", "v_tex"};

    /* renamed from: h */
    public static final FloatBuffer f6238h = C2354n.m2404K(new float[]{-1.0f, 1.0f, -1.0f, -1.0f, 1.0f, 1.0f, 1.0f, -1.0f});

    /* renamed from: l */
    public int f6242l;

    /* renamed from: n */
    public int f6244n;

    /* renamed from: q */
    @Nullable
    public VideoDecoderOutputBuffer f6247q;

    /* renamed from: i */
    public final int[] f6239i = new int[3];

    /* renamed from: j */
    public final AtomicReference<VideoDecoderOutputBuffer> f6240j = new AtomicReference<>();

    /* renamed from: k */
    public FloatBuffer[] f6241k = new FloatBuffer[3];

    /* renamed from: m */
    public int[] f6243m = new int[3];

    /* renamed from: o */
    public int[] f6245o = new int[3];

    /* renamed from: p */
    public int[] f6246p = new int[3];

    public C2381m(GLSurfaceView gLSurfaceView) {
        for (int i2 = 0; i2 < 3; i2++) {
            int[] iArr = this.f6245o;
            this.f6246p[i2] = -1;
            iArr[i2] = -1;
        }
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onDrawFrame(GL10 gl10) {
        VideoDecoderOutputBuffer andSet = this.f6240j.getAndSet(null);
        if (andSet == null && this.f6247q == null) {
            return;
        }
        if (andSet != null) {
            VideoDecoderOutputBuffer videoDecoderOutputBuffer = this.f6247q;
            if (videoDecoderOutputBuffer != null) {
                videoDecoderOutputBuffer.release();
            }
            this.f6247q = andSet;
        }
        VideoDecoderOutputBuffer videoDecoderOutputBuffer2 = this.f6247q;
        float[] fArr = f6235e;
        int i2 = videoDecoderOutputBuffer2.colorspace;
        if (i2 == 1) {
            fArr = f6234c;
        } else if (i2 == 3) {
            fArr = f6236f;
        }
        GLES20.glUniformMatrix3fv(this.f6244n, 1, false, fArr, 0);
        int i3 = 0;
        while (i3 < 3) {
            int i4 = i3 == 0 ? videoDecoderOutputBuffer2.height : (videoDecoderOutputBuffer2.height + 1) / 2;
            GLES20.glActiveTexture(33984 + i3);
            GLES20.glBindTexture(3553, this.f6239i[i3]);
            GLES20.glPixelStorei(3317, 1);
            GLES20.glTexImage2D(3553, 0, 6409, videoDecoderOutputBuffer2.yuvStrides[i3], i4, 0, 6409, 5121, videoDecoderOutputBuffer2.yuvPlanes[i3]);
            i3++;
        }
        int i5 = (r0[0] + 1) / 2;
        int[] iArr = {videoDecoderOutputBuffer2.width, i5, i5};
        for (int i6 = 0; i6 < 3; i6++) {
            if (this.f6245o[i6] != iArr[i6] || this.f6246p[i6] != videoDecoderOutputBuffer2.yuvStrides[i6]) {
                C4195m.m4771I(videoDecoderOutputBuffer2.yuvStrides[i6] != 0);
                float f2 = iArr[i6] / videoDecoderOutputBuffer2.yuvStrides[i6];
                this.f6241k[i6] = C2354n.m2404K(new float[]{0.0f, 0.0f, 0.0f, 1.0f, f2, 0.0f, f2, 1.0f});
                GLES20.glVertexAttribPointer(this.f6243m[i6], 2, 5126, false, 0, (Buffer) this.f6241k[i6]);
                this.f6245o[i6] = iArr[i6];
                this.f6246p[i6] = videoDecoderOutputBuffer2.yuvStrides[i6];
            }
        }
        GLES20.glClear(16384);
        GLES20.glDrawArrays(5, 0, 4);
        C2354n.m2527x();
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onSurfaceChanged(GL10 gl10, int i2, int i3) {
        GLES20.glViewport(0, 0, i2, i3);
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onSurfaceCreated(GL10 gl10, EGLConfig eGLConfig) {
        int m2392G = C2354n.m2392G("varying vec2 interp_tc_y;\nvarying vec2 interp_tc_u;\nvarying vec2 interp_tc_v;\nattribute vec4 in_pos;\nattribute vec2 in_tc_y;\nattribute vec2 in_tc_u;\nattribute vec2 in_tc_v;\nvoid main() {\n  gl_Position = in_pos;\n  interp_tc_y = in_tc_y;\n  interp_tc_u = in_tc_u;\n  interp_tc_v = in_tc_v;\n}\n", "precision mediump float;\nvarying vec2 interp_tc_y;\nvarying vec2 interp_tc_u;\nvarying vec2 interp_tc_v;\nuniform sampler2D y_tex;\nuniform sampler2D u_tex;\nuniform sampler2D v_tex;\nuniform mat3 mColorConversion;\nvoid main() {\n  vec3 yuv;\n  yuv.x = texture2D(y_tex, interp_tc_y).r - 0.0625;\n  yuv.y = texture2D(u_tex, interp_tc_u).r - 0.5;\n  yuv.z = texture2D(v_tex, interp_tc_v).r - 0.5;\n  gl_FragColor = vec4(mColorConversion * yuv, 1.0);\n}\n");
        this.f6242l = m2392G;
        GLES20.glUseProgram(m2392G);
        int glGetAttribLocation = GLES20.glGetAttribLocation(this.f6242l, "in_pos");
        GLES20.glEnableVertexAttribArray(glGetAttribLocation);
        GLES20.glVertexAttribPointer(glGetAttribLocation, 2, 5126, false, 0, (Buffer) f6238h);
        this.f6243m[0] = GLES20.glGetAttribLocation(this.f6242l, "in_tc_y");
        GLES20.glEnableVertexAttribArray(this.f6243m[0]);
        this.f6243m[1] = GLES20.glGetAttribLocation(this.f6242l, "in_tc_u");
        GLES20.glEnableVertexAttribArray(this.f6243m[1]);
        this.f6243m[2] = GLES20.glGetAttribLocation(this.f6242l, "in_tc_v");
        GLES20.glEnableVertexAttribArray(this.f6243m[2]);
        C2354n.m2527x();
        this.f6244n = GLES20.glGetUniformLocation(this.f6242l, "mColorConversion");
        C2354n.m2527x();
        GLES20.glGenTextures(3, this.f6239i, 0);
        for (int i2 = 0; i2 < 3; i2++) {
            GLES20.glUniform1i(GLES20.glGetUniformLocation(this.f6242l, f6237g[i2]), i2);
            GLES20.glActiveTexture(33984 + i2);
            GLES20.glBindTexture(3553, this.f6239i[i2]);
            GLES20.glTexParameterf(3553, 10241, 9729.0f);
            GLES20.glTexParameterf(3553, Data.MAX_DATA_BYTES, 9729.0f);
            GLES20.glTexParameterf(3553, 10242, 33071.0f);
            GLES20.glTexParameterf(3553, 10243, 33071.0f);
        }
        C2354n.m2527x();
        C2354n.m2527x();
    }
}
