package p005b.p199l.p200a.p201a.p236l1.p239o;

import android.graphics.Bitmap;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.zip.Inflater;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.o.a */
/* loaded from: classes.dex */
public final class C2226a extends AbstractC2208c {

    /* renamed from: n */
    public final C2360t f5450n;

    /* renamed from: o */
    public final C2360t f5451o;

    /* renamed from: p */
    public final a f5452p;

    /* renamed from: q */
    @Nullable
    public Inflater f5453q;

    /* renamed from: b.l.a.a.l1.o.a$a */
    public static final class a {

        /* renamed from: a */
        public final C2360t f5454a = new C2360t();

        /* renamed from: b */
        public final int[] f5455b = new int[256];

        /* renamed from: c */
        public boolean f5456c;

        /* renamed from: d */
        public int f5457d;

        /* renamed from: e */
        public int f5458e;

        /* renamed from: f */
        public int f5459f;

        /* renamed from: g */
        public int f5460g;

        /* renamed from: h */
        public int f5461h;

        /* renamed from: i */
        public int f5462i;

        /* renamed from: a */
        public void m2088a() {
            this.f5457d = 0;
            this.f5458e = 0;
            this.f5459f = 0;
            this.f5460g = 0;
            this.f5461h = 0;
            this.f5462i = 0;
            this.f5454a.m2593y(0);
            this.f5456c = false;
        }
    }

    public C2226a() {
        super("PgsDecoder");
        this.f5450n = new C2360t();
        this.f5451o = new C2360t();
        this.f5452p = new a();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z) {
        C2360t c2360t;
        C2207b c2207b;
        C2360t c2360t2;
        int i3;
        int i4;
        int m2587s;
        C2226a c2226a = this;
        C2360t c2360t3 = c2226a.f5450n;
        c2360t3.f6133a = bArr;
        c2360t3.f6135c = i2;
        int i5 = 0;
        c2360t3.f6134b = 0;
        if (c2360t3.m2569a() > 0 && c2360t3.m2570b() == 120) {
            if (c2226a.f5453q == null) {
                c2226a.f5453q = new Inflater();
            }
            if (C2344d0.m2344v(c2360t3, c2226a.f5451o, c2226a.f5453q)) {
                C2360t c2360t4 = c2226a.f5451o;
                c2360t3.m2565A(c2360t4.f6133a, c2360t4.f6135c);
            }
        }
        c2226a.f5452p.m2088a();
        ArrayList arrayList = new ArrayList();
        while (c2226a.f5450n.m2569a() >= 3) {
            C2360t c2360t5 = c2226a.f5450n;
            a aVar = c2226a.f5452p;
            int i6 = c2360t5.f6135c;
            int m2585q = c2360t5.m2585q();
            int m2590v = c2360t5.m2590v();
            int i7 = c2360t5.f6134b + m2590v;
            if (i7 > i6) {
                c2360t5.m2567C(i6);
                c2207b = null;
            } else {
                if (m2585q != 128) {
                    switch (m2585q) {
                        case 20:
                            Objects.requireNonNull(aVar);
                            if (m2590v % 5 == 2) {
                                c2360t5.m2568D(2);
                                Arrays.fill(aVar.f5455b, i5);
                                int i8 = m2590v / 5;
                                int i9 = 0;
                                while (i9 < i8) {
                                    int m2585q2 = c2360t5.m2585q();
                                    int m2585q3 = c2360t5.m2585q();
                                    double d2 = m2585q3;
                                    double m2585q4 = c2360t5.m2585q() - 128;
                                    arrayList = arrayList;
                                    double m2585q5 = c2360t5.m2585q() - 128;
                                    aVar.f5455b[m2585q2] = (C2344d0.m2329g((int) ((1.402d * m2585q4) + d2), 0, 255) << 16) | (c2360t5.m2585q() << 24) | (C2344d0.m2329g((int) ((d2 - (0.34414d * m2585q5)) - (m2585q4 * 0.71414d)), 0, 255) << 8) | C2344d0.m2329g((int) ((m2585q5 * 1.772d) + d2), 0, 255);
                                    i9++;
                                    c2360t5 = c2360t5;
                                }
                                c2360t = c2360t5;
                                aVar.f5456c = true;
                                break;
                            }
                            c2360t = c2360t5;
                            break;
                        case 21:
                            Objects.requireNonNull(aVar);
                            if (m2590v >= 4) {
                                c2360t5.m2568D(3);
                                int i10 = m2590v - 4;
                                if ((c2360t5.m2585q() & 128) != 0) {
                                    if (i10 >= 7 && (m2587s = c2360t5.m2587s()) >= 4) {
                                        aVar.f5461h = c2360t5.m2590v();
                                        aVar.f5462i = c2360t5.m2590v();
                                        aVar.f5454a.m2593y(m2587s - 4);
                                        i10 -= 7;
                                    }
                                }
                                C2360t c2360t6 = aVar.f5454a;
                                int i11 = c2360t6.f6134b;
                                int i12 = c2360t6.f6135c;
                                if (i11 < i12 && i10 > 0) {
                                    int min = Math.min(i10, i12 - i11);
                                    c2360t5.m2572d(aVar.f5454a.f6133a, i11, min);
                                    aVar.f5454a.m2567C(i11 + min);
                                }
                            }
                            c2360t = c2360t5;
                            break;
                        case 22:
                            Objects.requireNonNull(aVar);
                            if (m2590v >= 19) {
                                aVar.f5457d = c2360t5.m2590v();
                                aVar.f5458e = c2360t5.m2590v();
                                c2360t5.m2568D(11);
                                aVar.f5459f = c2360t5.m2590v();
                                aVar.f5460g = c2360t5.m2590v();
                            }
                            c2360t = c2360t5;
                            break;
                        default:
                            c2360t = c2360t5;
                            break;
                    }
                    c2207b = null;
                } else {
                    c2360t = c2360t5;
                    if (aVar.f5457d == 0 || aVar.f5458e == 0 || aVar.f5461h == 0 || aVar.f5462i == 0 || (i3 = (c2360t2 = aVar.f5454a).f6135c) == 0 || c2360t2.f6134b != i3 || !aVar.f5456c) {
                        c2207b = null;
                    } else {
                        c2360t2.m2567C(0);
                        int i13 = aVar.f5461h * aVar.f5462i;
                        int[] iArr = new int[i13];
                        int i14 = 0;
                        while (i14 < i13) {
                            int m2585q6 = aVar.f5454a.m2585q();
                            if (m2585q6 != 0) {
                                i4 = i14 + 1;
                                iArr[i14] = aVar.f5455b[m2585q6];
                            } else {
                                int m2585q7 = aVar.f5454a.m2585q();
                                if (m2585q7 != 0) {
                                    i4 = ((m2585q7 & 64) == 0 ? m2585q7 & 63 : ((m2585q7 & 63) << 8) | aVar.f5454a.m2585q()) + i14;
                                    Arrays.fill(iArr, i14, i4, (m2585q7 & 128) == 0 ? 0 : aVar.f5455b[aVar.f5454a.m2585q()]);
                                }
                            }
                            i14 = i4;
                        }
                        Bitmap createBitmap = Bitmap.createBitmap(iArr, aVar.f5461h, aVar.f5462i, Bitmap.Config.ARGB_8888);
                        float f2 = aVar.f5459f;
                        float f3 = aVar.f5457d;
                        float f4 = f2 / f3;
                        float f5 = aVar.f5460g;
                        float f6 = aVar.f5458e;
                        c2207b = new C2207b(createBitmap, f4, 0, f5 / f6, 0, aVar.f5461h / f3, aVar.f5462i / f6);
                    }
                    aVar.m2088a();
                }
                c2360t.m2567C(i7);
            }
            ArrayList arrayList2 = arrayList;
            if (c2207b != null) {
                arrayList2.add(c2207b);
            }
            arrayList = arrayList2;
            i5 = 0;
            c2226a = this;
        }
        return new C2227b(Collections.unmodifiableList(arrayList));
    }
}
