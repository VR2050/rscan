package p005b.p199l.p200a.p201a.p246n1.p247h;

import android.graphics.SurfaceTexture;
import android.media.MediaFormat;
import android.opengl.GLES20;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import androidx.work.Data;
import com.google.android.exoplayer2.Format;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p199l.p200a.p201a.p250p1.C2340b0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2382n;
import p005b.p199l.p200a.p201a.p251q1.p252s.C2389c;
import p005b.p199l.p200a.p201a.p251q1.p252s.C2390d;
import p005b.p199l.p200a.p201a.p251q1.p252s.InterfaceC2387a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.n1.h.f */
/* loaded from: classes.dex */
public final class C2275f implements InterfaceC2382n, InterfaceC2387a {

    /* renamed from: i */
    public int f5752i;

    /* renamed from: j */
    public SurfaceTexture f5753j;

    /* renamed from: m */
    @Nullable
    public byte[] f5756m;

    /* renamed from: a */
    public final AtomicBoolean f5744a = new AtomicBoolean();

    /* renamed from: b */
    public final AtomicBoolean f5745b = new AtomicBoolean(true);

    /* renamed from: c */
    public final C2274e f5746c = new C2274e();

    /* renamed from: d */
    public final C2389c f5747d = new C2389c();

    /* renamed from: e */
    public final C2340b0<Long> f5748e = new C2340b0<>();

    /* renamed from: f */
    public final C2340b0<C2390d> f5749f = new C2340b0<>();

    /* renamed from: g */
    public final float[] f5750g = new float[16];

    /* renamed from: h */
    public final float[] f5751h = new float[16];

    /* renamed from: k */
    public volatile int f5754k = 0;

    /* renamed from: l */
    public int f5755l = -1;

    @Override // p005b.p199l.p200a.p201a.p251q1.p252s.InterfaceC2387a
    /* renamed from: a */
    public void mo2174a(long j2, float[] fArr) {
        this.f5747d.f6277c.m2300a(j2, fArr);
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.p252s.InterfaceC2387a
    /* renamed from: b */
    public void mo2175b() {
        this.f5748e.m2301b();
        C2389c c2389c = this.f5747d;
        c2389c.f6277c.m2301b();
        c2389c.f6278d = false;
        this.f5745b.set(true);
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2382n
    /* renamed from: c */
    public void mo2176c(long j2, long j3, Format format, @Nullable MediaFormat mediaFormat) {
        float f2;
        float f3;
        int i2;
        int i3;
        ArrayList<C2390d.a> arrayList;
        int m2573e;
        this.f5748e.m2300a(j3, Long.valueOf(j2));
        byte[] bArr = format.f9256w;
        int i4 = format.f9255v;
        byte[] bArr2 = this.f5756m;
        int i5 = this.f5755l;
        this.f5756m = bArr;
        if (i4 == -1) {
            i4 = this.f5754k;
        }
        this.f5755l = i4;
        if (i5 == i4 && Arrays.equals(bArr2, this.f5756m)) {
            return;
        }
        byte[] bArr3 = this.f5756m;
        C2390d c2390d = null;
        if (bArr3 != null) {
            int i6 = this.f5755l;
            C2360t c2360t = new C2360t(bArr3);
            try {
                c2360t.m2568D(4);
                m2573e = c2360t.m2573e();
                c2360t.m2567C(0);
            } catch (ArrayIndexOutOfBoundsException unused) {
            }
            if (m2573e == 1886547818) {
                c2360t.m2568D(8);
                int i7 = c2360t.f6134b;
                int i8 = c2360t.f6135c;
                while (i7 < i8) {
                    int m2573e2 = c2360t.m2573e() + i7;
                    if (m2573e2 <= i7 || m2573e2 > i8) {
                        break;
                    }
                    int m2573e3 = c2360t.m2573e();
                    if (m2573e3 != 2037673328 && m2573e3 != 1836279920) {
                        c2360t.m2567C(m2573e2);
                        i7 = m2573e2;
                    }
                    c2360t.m2566B(m2573e2);
                    arrayList = C2354n.m2493l1(c2360t);
                    break;
                }
                arrayList = null;
            } else {
                arrayList = C2354n.m2493l1(c2360t);
            }
            if (arrayList != null) {
                int size = arrayList.size();
                if (size == 1) {
                    c2390d = new C2390d(arrayList.get(0), i6);
                } else if (size == 2) {
                    c2390d = new C2390d(arrayList.get(0), arrayList.get(1), i6);
                }
            }
        }
        if (c2390d == null || !C2274e.m2173a(c2390d)) {
            int i9 = this.f5755l;
            C4195m.m4765F(true);
            C4195m.m4765F(true);
            C4195m.m4765F(true);
            C4195m.m4765F(true);
            C4195m.m4765F(true);
            float radians = (float) Math.toRadians(180.0f);
            float radians2 = (float) Math.toRadians(360.0f);
            float f4 = radians / 36;
            float f5 = radians2 / 72;
            float[] fArr = new float[15984];
            float[] fArr2 = new float[10656];
            int i10 = 0;
            int i11 = 0;
            int i12 = 0;
            for (int i13 = 36; i10 < i13; i13 = 36) {
                float f6 = radians / 2.0f;
                float f7 = (i10 * f4) - f6;
                int i14 = i10 + 1;
                float f8 = (i14 * f4) - f6;
                int i15 = 0;
                while (i15 < 73) {
                    int i16 = i14;
                    int i17 = 0;
                    for (int i18 = 2; i17 < i18; i18 = 2) {
                        if (i17 == 0) {
                            f3 = f8;
                            f2 = f7;
                        } else {
                            f2 = f8;
                            f3 = f2;
                        }
                        float f9 = i15 * f5;
                        float f10 = f7;
                        int i19 = i11 + 1;
                        float f11 = f5;
                        double d2 = 50.0f;
                        int i20 = i15;
                        double d3 = (f9 + 3.1415927f) - (radians2 / 2.0f);
                        int i21 = i9;
                        float f12 = radians;
                        double d4 = f2;
                        float f13 = f4;
                        fArr[i11] = -((float) (Math.cos(d4) * Math.sin(d3) * d2));
                        int i22 = i19 + 1;
                        int i23 = i17;
                        fArr[i19] = (float) (Math.sin(d4) * d2);
                        int i24 = i22 + 1;
                        fArr[i22] = (float) (Math.cos(d4) * Math.cos(d3) * d2);
                        int i25 = i12 + 1;
                        fArr2[i12] = f9 / radians2;
                        int i26 = i25 + 1;
                        fArr2[i25] = ((i10 + i23) * f13) / f12;
                        if (i20 == 0 && i23 == 0) {
                            i3 = i23;
                            i2 = i20;
                        } else {
                            i2 = i20;
                            i3 = i23;
                            if (i2 != 72 || i3 != 1) {
                                i12 = i26;
                                i11 = i24;
                                i17 = i3 + 1;
                                i15 = i2;
                                f8 = f3;
                                f5 = f11;
                                f7 = f10;
                                radians = f12;
                                f4 = f13;
                                i9 = i21;
                            }
                        }
                        System.arraycopy(fArr, i24 - 3, fArr, i24, 3);
                        i24 += 3;
                        System.arraycopy(fArr2, i26 - 2, fArr2, i26, 2);
                        i26 += 2;
                        i12 = i26;
                        i11 = i24;
                        i17 = i3 + 1;
                        i15 = i2;
                        f8 = f3;
                        f5 = f11;
                        f7 = f10;
                        radians = f12;
                        f4 = f13;
                        i9 = i21;
                    }
                    i15++;
                    i14 = i16;
                    f8 = f8;
                    i9 = i9;
                }
                i10 = i14;
            }
            c2390d = new C2390d(new C2390d.a(new C2390d.b(0, fArr, fArr2, 1)), i9);
        }
        this.f5749f.m2300a(j3, c2390d);
    }

    /* renamed from: d */
    public SurfaceTexture m2177d() {
        GLES20.glClearColor(0.5f, 0.5f, 0.5f, 1.0f);
        C2354n.m2527x();
        C2274e c2274e = this.f5746c;
        Objects.requireNonNull(c2274e);
        int m2392G = C2354n.m2392G(TextUtils.join("\n", C2274e.f5724a), TextUtils.join("\n", C2274e.f5725b));
        c2274e.f5734k = m2392G;
        c2274e.f5735l = GLES20.glGetUniformLocation(m2392G, "uMvpMatrix");
        c2274e.f5736m = GLES20.glGetUniformLocation(c2274e.f5734k, "uTexMatrix");
        c2274e.f5737n = GLES20.glGetAttribLocation(c2274e.f5734k, "aPosition");
        c2274e.f5738o = GLES20.glGetAttribLocation(c2274e.f5734k, "aTexCoords");
        c2274e.f5739p = GLES20.glGetUniformLocation(c2274e.f5734k, "uTexture");
        C2354n.m2527x();
        int[] iArr = new int[1];
        GLES20.glGenTextures(1, IntBuffer.wrap(iArr));
        GLES20.glBindTexture(36197, iArr[0]);
        GLES20.glTexParameteri(36197, 10241, 9729);
        GLES20.glTexParameteri(36197, Data.MAX_DATA_BYTES, 9729);
        GLES20.glTexParameteri(36197, 10242, 33071);
        GLES20.glTexParameteri(36197, 10243, 33071);
        C2354n.m2527x();
        this.f5752i = iArr[0];
        SurfaceTexture surfaceTexture = new SurfaceTexture(this.f5752i);
        this.f5753j = surfaceTexture;
        surfaceTexture.setOnFrameAvailableListener(new SurfaceTexture.OnFrameAvailableListener() { // from class: b.l.a.a.n1.h.a
            @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
            public final void onFrameAvailable(SurfaceTexture surfaceTexture2) {
                C2275f.this.f5744a.set(true);
            }
        });
        return this.f5753j;
    }
}
