package p005b.p362y.p363a.p369i.p371c;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.graphics.SurfaceTexture;
import android.opengl.GLES20;
import android.opengl.GLException;
import android.opengl.Matrix;
import android.view.Surface;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.work.Data;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.util.Objects;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;
import p005b.p362y.p363a.p366f.InterfaceC2928d;
import p005b.p362y.p363a.p369i.p370b.C2940a;

@SuppressLint({"ViewConstructor"})
/* renamed from: b.y.a.i.c.c */
/* loaded from: classes2.dex */
public class C2943c extends AbstractC2942b {

    /* renamed from: o */
    public final float[] f8064o;

    /* renamed from: p */
    public int f8065p;

    /* renamed from: r */
    public int f8067r;

    /* renamed from: s */
    public int f8068s;

    /* renamed from: t */
    public int f8069t;

    /* renamed from: u */
    public int f8070u;

    /* renamed from: x */
    public FloatBuffer f8073x;

    /* renamed from: y */
    public SurfaceTexture f8074y;

    /* renamed from: z */
    public InterfaceC2928d f8075z;

    /* renamed from: q */
    public int[] f8066q = new int[2];

    /* renamed from: v */
    public boolean f8071v = false;

    /* renamed from: w */
    public boolean f8072w = false;

    /* renamed from: A */
    public GSYVideoGLView.InterfaceC4091c f8063A = new C2940a();

    public C2943c() {
        float[] fArr = {-1.0f, -1.0f, 0.0f, 0.0f, 0.0f, 1.0f, -1.0f, 0.0f, 1.0f, 0.0f, -1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f};
        this.f8064o = fArr;
        FloatBuffer asFloatBuffer = ByteBuffer.allocateDirect(fArr.length * 4).order(ByteOrder.nativeOrder()).asFloatBuffer();
        this.f8073x = asFloatBuffer;
        asFloatBuffer.put(fArr).position(0);
        Matrix.setIdentityM(this.f8053h, 0);
        Matrix.setIdentityM(this.f8052g, 0);
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onDrawFrame(GL10 gl10) {
        Bitmap bitmap;
        synchronized (this) {
            if (this.f8071v) {
                this.f8074y.updateTexImage();
                this.f8074y.getTransformMatrix(this.f8053h);
                this.f8071v = false;
            }
        }
        if (this.f8056k) {
            Objects.requireNonNull(this.f8063A);
            this.f8065p = m3406b("uniform mat4 uMVPMatrix;\nuniform mat4 uSTMatrix;\nattribute vec4 aPosition;\nattribute vec4 aTextureCoord;\nvarying vec2 vTextureCoord;\nvoid main() {\n  gl_Position = uMVPMatrix * aPosition;\n  vTextureCoord = (uSTMatrix * aTextureCoord).xy;\n}\n", "#extension GL_OES_EGL_image_external : require\nprecision mediump float;\nvarying vec2 vTextureCoord;\nuniform samplerExternalOES sTexture;\nvoid main() {\n  gl_FragColor = texture2D(sTexture, vTextureCoord);\n}\n");
            this.f8056k = false;
        }
        GLES20.glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        GLES20.glClear(16640);
        GLES20.glUseProgram(this.f8065p);
        m3405a("glUseProgram");
        GLES20.glActiveTexture(33984);
        GLES20.glBindTexture(36197, this.f8066q[0]);
        this.f8073x.position(0);
        GLES20.glVertexAttribPointer(this.f8069t, 3, 5126, false, 20, (Buffer) this.f8073x);
        m3405a("glVertexAttribPointer maPosition");
        GLES20.glEnableVertexAttribArray(this.f8069t);
        m3405a("glEnableVertexAttribArray maPositionHandle");
        this.f8073x.position(3);
        GLES20.glVertexAttribPointer(this.f8070u, 3, 5126, false, 20, (Buffer) this.f8073x);
        m3405a("glVertexAttribPointer maTextureHandle");
        GLES20.glEnableVertexAttribArray(this.f8070u);
        m3405a("glEnableVertexAttribArray maTextureHandle");
        GLES20.glUniformMatrix4fv(this.f8067r, 1, false, this.f8052g, 0);
        GLES20.glUniformMatrix4fv(this.f8068s, 1, false, this.f8053h, 0);
        GLES20.glDrawArrays(5, 0, 4);
        m3405a("glDrawArrays");
        if (this.f8072w) {
            this.f8072w = false;
            if (this.f8075z != null) {
                int width = this.f8051f.getWidth();
                int height = this.f8051f.getHeight();
                int i2 = width * height;
                int[] iArr = new int[i2];
                int[] iArr2 = new int[i2];
                IntBuffer wrap = IntBuffer.wrap(iArr);
                wrap.position(0);
                try {
                    gl10.glReadPixels(0, 0, width, height, 6408, 5121, wrap);
                    for (int i3 = 0; i3 < height; i3++) {
                        int i4 = i3 * width;
                        int i5 = ((height - i3) - 1) * width;
                        for (int i6 = 0; i6 < width; i6++) {
                            int i7 = iArr[i4 + i6];
                            iArr2[i5 + i6] = (i7 & (-16711936)) | ((i7 << 16) & ItemTouchHelper.ACTION_MODE_DRAG_MASK) | ((i7 >> 16) & 255);
                        }
                    }
                    bitmap = this.f8049c ? Bitmap.createBitmap(iArr2, width, height, Bitmap.Config.ARGB_8888) : Bitmap.createBitmap(iArr2, width, height, Bitmap.Config.RGB_565);
                } catch (GLException unused) {
                    bitmap = null;
                }
                ((GSYVideoGLView.C4089a) this.f8075z).m4638a(bitmap);
            }
        }
        GLES20.glFinish();
    }

    @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
    public synchronized void onFrameAvailable(SurfaceTexture surfaceTexture) {
        this.f8071v = true;
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onSurfaceChanged(GL10 gl10, int i2, int i3) {
        GLES20.glViewport(0, 0, i2, i3);
    }

    @Override // android.opengl.GLSurfaceView.Renderer
    public void onSurfaceCreated(GL10 gl10, EGLConfig eGLConfig) {
        Objects.requireNonNull(this.f8063A);
        int m3406b = m3406b("uniform mat4 uMVPMatrix;\nuniform mat4 uSTMatrix;\nattribute vec4 aPosition;\nattribute vec4 aTextureCoord;\nvarying vec2 vTextureCoord;\nvoid main() {\n  gl_Position = uMVPMatrix * aPosition;\n  vTextureCoord = (uSTMatrix * aTextureCoord).xy;\n}\n", "#extension GL_OES_EGL_image_external : require\nprecision mediump float;\nvarying vec2 vTextureCoord;\nuniform samplerExternalOES sTexture;\nvoid main() {\n  gl_FragColor = texture2D(sTexture, vTextureCoord);\n}\n");
        this.f8065p = m3406b;
        if (m3406b == 0) {
            return;
        }
        this.f8069t = GLES20.glGetAttribLocation(m3406b, "aPosition");
        m3405a("glGetAttribLocation aPosition");
        if (this.f8069t == -1) {
            throw new RuntimeException("Could not get attrib location for aPosition");
        }
        this.f8070u = GLES20.glGetAttribLocation(this.f8065p, "aTextureCoord");
        m3405a("glGetAttribLocation aTextureCoord");
        if (this.f8070u == -1) {
            throw new RuntimeException("Could not get attrib location for aTextureCoord");
        }
        this.f8067r = GLES20.glGetUniformLocation(this.f8065p, "uMVPMatrix");
        m3405a("glGetUniformLocation uMVPMatrix");
        if (this.f8067r == -1) {
            throw new RuntimeException("Could not get attrib location for uMVPMatrix");
        }
        this.f8068s = GLES20.glGetUniformLocation(this.f8065p, "uSTMatrix");
        m3405a("glGetUniformLocation uSTMatrix");
        if (this.f8068s == -1) {
            throw new RuntimeException("Could not get attrib location for uSTMatrix");
        }
        GLES20.glGenTextures(2, this.f8066q, 0);
        GLES20.glBindTexture(36197, this.f8066q[0]);
        m3405a("glBindTexture mTextureID");
        GLES20.glTexParameteri(3553, 10241, 9729);
        GLES20.glTexParameteri(3553, Data.MAX_DATA_BYTES, 9729);
        GLES20.glTexParameteri(3553, 10242, 33071);
        GLES20.glTexParameteri(3553, 10243, 33071);
        SurfaceTexture surfaceTexture = new SurfaceTexture(this.f8066q[0]);
        this.f8074y = surfaceTexture;
        surfaceTexture.setOnFrameAvailableListener(this);
        this.f8059n.post(new RunnableC2941a(this, new Surface(this.f8074y)));
    }
}
