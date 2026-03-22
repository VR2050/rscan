package p005b.p199l.p200a.p201a.p246n1.p247h;

import androidx.annotation.Nullable;
import java.nio.FloatBuffer;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p251q1.p252s.C2390d;

/* renamed from: b.l.a.a.n1.h.e */
/* loaded from: classes.dex */
public final class C2274e {

    /* renamed from: a */
    public static final String[] f5724a = {"uniform mat4 uMvpMatrix;", "uniform mat3 uTexMatrix;", "attribute vec4 aPosition;", "attribute vec2 aTexCoords;", "varying vec2 vTexCoords;", "void main() {", "  gl_Position = uMvpMatrix * aPosition;", "  vTexCoords = (uTexMatrix * vec3(aTexCoords, 1)).xy;", "}"};

    /* renamed from: b */
    public static final String[] f5725b = {"#extension GL_OES_EGL_image_external : require", "precision mediump float;", "uniform samplerExternalOES uTexture;", "varying vec2 vTexCoords;", "void main() {", "  gl_FragColor = texture2D(uTexture, vTexCoords);", "}"};

    /* renamed from: c */
    public static final float[] f5726c = {1.0f, 0.0f, 0.0f, 0.0f, -1.0f, 0.0f, 0.0f, 1.0f, 1.0f};

    /* renamed from: d */
    public static final float[] f5727d = {1.0f, 0.0f, 0.0f, 0.0f, -0.5f, 0.0f, 0.0f, 0.5f, 1.0f};

    /* renamed from: e */
    public static final float[] f5728e = {1.0f, 0.0f, 0.0f, 0.0f, -0.5f, 0.0f, 0.0f, 1.0f, 1.0f};

    /* renamed from: f */
    public static final float[] f5729f = {0.5f, 0.0f, 0.0f, 0.0f, -1.0f, 0.0f, 0.0f, 1.0f, 1.0f};

    /* renamed from: g */
    public static final float[] f5730g = {0.5f, 0.0f, 0.0f, 0.0f, -1.0f, 0.0f, 0.5f, 1.0f, 1.0f};

    /* renamed from: h */
    public int f5731h;

    /* renamed from: i */
    @Nullable
    public a f5732i;

    /* renamed from: j */
    @Nullable
    public a f5733j;

    /* renamed from: k */
    public int f5734k;

    /* renamed from: l */
    public int f5735l;

    /* renamed from: m */
    public int f5736m;

    /* renamed from: n */
    public int f5737n;

    /* renamed from: o */
    public int f5738o;

    /* renamed from: p */
    public int f5739p;

    /* renamed from: b.l.a.a.n1.h.e$a */
    public static class a {

        /* renamed from: a */
        public final int f5740a;

        /* renamed from: b */
        public final FloatBuffer f5741b;

        /* renamed from: c */
        public final FloatBuffer f5742c;

        /* renamed from: d */
        public final int f5743d;

        public a(C2390d.b bVar) {
            float[] fArr = bVar.f6286c;
            this.f5740a = fArr.length / 3;
            this.f5741b = C2354n.m2404K(fArr);
            this.f5742c = C2354n.m2404K(bVar.f6287d);
            int i2 = bVar.f6285b;
            if (i2 == 1) {
                this.f5743d = 5;
            } else if (i2 != 2) {
                this.f5743d = 4;
            } else {
                this.f5743d = 6;
            }
        }
    }

    /* renamed from: a */
    public static boolean m2173a(C2390d c2390d) {
        C2390d.a aVar = c2390d.f6279a;
        C2390d.a aVar2 = c2390d.f6280b;
        C2390d.b[] bVarArr = aVar.f6283a;
        if (bVarArr.length == 1 && bVarArr[0].f6284a == 0) {
            C2390d.b[] bVarArr2 = aVar2.f6283a;
            if (bVarArr2.length == 1 && bVarArr2[0].f6284a == 0) {
                return true;
            }
        }
        return false;
    }
}
