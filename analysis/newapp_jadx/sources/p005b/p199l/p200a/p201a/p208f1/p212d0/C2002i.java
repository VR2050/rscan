package p005b.p199l.p200a.p201a.p208f1.p212d0;

import com.google.android.exoplayer2.Format;
import java.util.ArrayList;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2053t;
import p005b.p199l.p200a.p201a.p208f1.C2054u;
import p005b.p199l.p200a.p201a.p208f1.C2055v;
import p005b.p199l.p200a.p201a.p208f1.C2056w;
import p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.d0.i */
/* loaded from: classes.dex */
public final class C2002i extends AbstractC2001h {

    /* renamed from: n */
    public a f3777n;

    /* renamed from: o */
    public int f3778o;

    /* renamed from: p */
    public boolean f3779p;

    /* renamed from: q */
    public C2056w f3780q;

    /* renamed from: r */
    public C2054u f3781r;

    /* renamed from: b.l.a.a.f1.d0.i$a */
    public static final class a {

        /* renamed from: a */
        public final C2056w f3782a;

        /* renamed from: b */
        public final byte[] f3783b;

        /* renamed from: c */
        public final C2055v[] f3784c;

        /* renamed from: d */
        public final int f3785d;

        public a(C2056w c2056w, C2054u c2054u, byte[] bArr, C2055v[] c2055vArr, int i2) {
            this.f3782a = c2056w;
            this.f3783b = bArr;
            this.f3784c = c2055vArr;
            this.f3785d = i2;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: b */
    public void mo1560b(long j2) {
        this.f3768g = j2;
        this.f3779p = j2 != 0;
        C2056w c2056w = this.f3780q;
        this.f3778o = c2056w != null ? c2056w.f4208d : 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: c */
    public long mo1550c(C2360t c2360t) {
        byte[] bArr = c2360t.f6133a;
        if ((bArr[0] & 1) == 1) {
            return -1L;
        }
        byte b2 = bArr[0];
        a aVar = this.f3777n;
        int i2 = !aVar.f3784c[(b2 >> 1) & (255 >>> (8 - aVar.f3785d))].f4204a ? aVar.f3782a.f4208d : aVar.f3782a.f4209e;
        long j2 = this.f3779p ? (this.f3778o + i2) / 4 : 0;
        c2360t.m2566B(c2360t.f6135c + 4);
        byte[] bArr2 = c2360t.f6133a;
        int i3 = c2360t.f6135c;
        bArr2[i3 - 4] = (byte) (j2 & 255);
        bArr2[i3 - 3] = (byte) ((j2 >>> 8) & 255);
        bArr2[i3 - 2] = (byte) ((j2 >>> 16) & 255);
        bArr2[i3 - 1] = (byte) ((j2 >>> 24) & 255);
        this.f3779p = true;
        this.f3778o = i2;
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: d */
    public boolean mo1551d(C2360t c2360t, long j2, AbstractC2001h.b bVar) {
        a aVar;
        if (this.f3777n != null) {
            return false;
        }
        if (this.f3780q == null) {
            C4195m.m4780M0(1, c2360t, false);
            long m2576h = c2360t.m2576h();
            int m2585q = c2360t.m2585q();
            long m2576h2 = c2360t.m2576h();
            int m2575g = c2360t.m2575g();
            int m2575g2 = c2360t.m2575g();
            int m2575g3 = c2360t.m2575g();
            int m2585q2 = c2360t.m2585q();
            this.f3780q = new C2056w(m2576h, m2585q, m2576h2, m2575g, m2575g2, m2575g3, (int) Math.pow(2.0d, m2585q2 & 15), (int) Math.pow(2.0d, (m2585q2 & 240) >> 4), (c2360t.m2585q() & 1) > 0, Arrays.copyOf(c2360t.f6133a, c2360t.f6135c));
        } else if (this.f3781r == null) {
            this.f3781r = C4195m.m4768G0(c2360t, true, true);
        } else {
            int i2 = c2360t.f6135c;
            byte[] bArr = new byte[i2];
            int i3 = 0;
            System.arraycopy(c2360t.f6133a, 0, bArr, 0, i2);
            int i4 = this.f3780q.f4205a;
            int i5 = 5;
            C4195m.m4780M0(5, c2360t, false);
            int m2585q3 = c2360t.m2585q() + 1;
            C2053t c2053t = new C2053t(c2360t.f6133a);
            c2053t.m1639c(c2360t.f6134b * 8);
            int i6 = 0;
            while (i6 < m2585q3) {
                if (c2053t.m1638b(24) != 5653314) {
                    StringBuilder m586H = C1499a.m586H("expected code book to start with [0x56, 0x43, 0x42] at ");
                    m586H.append((c2053t.f4201c * 8) + c2053t.f4202d);
                    throw new C2205l0(m586H.toString());
                }
                int m1638b = c2053t.m1638b(16);
                int m1638b2 = c2053t.m1638b(24);
                long[] jArr = new long[m1638b2];
                if (c2053t.m1637a()) {
                    int m1638b3 = c2053t.m1638b(5) + 1;
                    int i7 = 0;
                    while (i7 < m1638b2) {
                        int m1638b4 = c2053t.m1638b(C4195m.m4825p0(m1638b2 - i7));
                        for (int i8 = 0; i8 < m1638b4 && i7 < m1638b2; i8++) {
                            jArr[i7] = m1638b3;
                            i7++;
                        }
                        m1638b3++;
                    }
                } else {
                    boolean m1637a = c2053t.m1637a();
                    while (i3 < m1638b2) {
                        if (!m1637a) {
                            jArr[i3] = c2053t.m1638b(5) + 1;
                        } else if (c2053t.m1637a()) {
                            jArr[i3] = c2053t.m1638b(5) + 1;
                        } else {
                            jArr[i3] = 0;
                        }
                        i3++;
                    }
                }
                int m1638b5 = c2053t.m1638b(4);
                if (m1638b5 > 2) {
                    throw new C2205l0(C1499a.m626l("lookup type greater than 2 not decodable: ", m1638b5));
                }
                if (m1638b5 == 1 || m1638b5 == 2) {
                    c2053t.m1639c(32);
                    c2053t.m1639c(32);
                    int m1638b6 = c2053t.m1638b(4) + 1;
                    c2053t.m1639c(1);
                    c2053t.m1639c((int) (m1638b6 * (m1638b5 == 1 ? m1638b != 0 ? (long) Math.floor(Math.pow(m1638b2, 1.0d / m1638b)) : 0L : m1638b2 * m1638b)));
                }
                i6++;
                i3 = 0;
            }
            int i9 = 6;
            int m1638b7 = c2053t.m1638b(6) + 1;
            for (int i10 = 0; i10 < m1638b7; i10++) {
                if (c2053t.m1638b(16) != 0) {
                    throw new C2205l0("placeholder of time domain transforms not zeroed out");
                }
            }
            int i11 = 1;
            int m1638b8 = c2053t.m1638b(6) + 1;
            int i12 = 0;
            while (true) {
                int i13 = 3;
                if (i12 < m1638b8) {
                    int m1638b9 = c2053t.m1638b(16);
                    if (m1638b9 == 0) {
                        int i14 = 8;
                        c2053t.m1639c(8);
                        c2053t.m1639c(16);
                        c2053t.m1639c(16);
                        c2053t.m1639c(6);
                        c2053t.m1639c(8);
                        int m1638b10 = c2053t.m1638b(4) + 1;
                        int i15 = 0;
                        while (i15 < m1638b10) {
                            c2053t.m1639c(i14);
                            i15++;
                            i14 = 8;
                        }
                    } else {
                        if (m1638b9 != i11) {
                            throw new C2205l0(C1499a.m626l("floor type greater than 1 not decodable: ", m1638b9));
                        }
                        int m1638b11 = c2053t.m1638b(i5);
                        int[] iArr = new int[m1638b11];
                        int i16 = -1;
                        for (int i17 = 0; i17 < m1638b11; i17++) {
                            iArr[i17] = c2053t.m1638b(4);
                            if (iArr[i17] > i16) {
                                i16 = iArr[i17];
                            }
                        }
                        int i18 = i16 + 1;
                        int[] iArr2 = new int[i18];
                        int i19 = 0;
                        while (i19 < i18) {
                            iArr2[i19] = c2053t.m1638b(i13) + 1;
                            int m1638b12 = c2053t.m1638b(2);
                            int i20 = 8;
                            if (m1638b12 > 0) {
                                c2053t.m1639c(8);
                            }
                            int i21 = 0;
                            for (int i22 = 1; i21 < (i22 << m1638b12); i22 = 1) {
                                c2053t.m1639c(i20);
                                i21++;
                                i20 = 8;
                            }
                            i19++;
                            i13 = 3;
                        }
                        c2053t.m1639c(2);
                        int m1638b13 = c2053t.m1638b(4);
                        int i23 = 0;
                        int i24 = 0;
                        for (int i25 = 0; i25 < m1638b11; i25++) {
                            i23 += iArr2[iArr[i25]];
                            while (i24 < i23) {
                                c2053t.m1639c(m1638b13);
                                i24++;
                            }
                        }
                    }
                    i12++;
                    i5 = 5;
                    i11 = 1;
                    i9 = 6;
                } else {
                    int m1638b14 = c2053t.m1638b(i9);
                    int i26 = 1;
                    int i27 = m1638b14 + 1;
                    int i28 = 0;
                    while (i28 < i27) {
                        if (c2053t.m1638b(16) > 2) {
                            throw new C2205l0("residueType greater than 2 is not decodable");
                        }
                        c2053t.m1639c(24);
                        c2053t.m1639c(24);
                        c2053t.m1639c(24);
                        int m1638b15 = c2053t.m1638b(6) + i26;
                        int i29 = 8;
                        c2053t.m1639c(8);
                        int[] iArr3 = new int[m1638b15];
                        for (int i30 = 0; i30 < m1638b15; i30++) {
                            iArr3[i30] = ((c2053t.m1637a() ? c2053t.m1638b(5) : 0) * 8) + c2053t.m1638b(3);
                        }
                        int i31 = 0;
                        while (i31 < m1638b15) {
                            int i32 = 0;
                            while (i32 < i29) {
                                if ((iArr3[i31] & (1 << i32)) != 0) {
                                    c2053t.m1639c(i29);
                                }
                                i32++;
                                i29 = 8;
                            }
                            i31++;
                            i29 = 8;
                        }
                        i28++;
                        i26 = 1;
                    }
                    int m1638b16 = c2053t.m1638b(6) + 1;
                    for (int i33 = 0; i33 < m1638b16; i33++) {
                        if (c2053t.m1638b(16) == 0) {
                            int m1638b17 = c2053t.m1637a() ? c2053t.m1638b(4) + 1 : 1;
                            if (c2053t.m1637a()) {
                                int m1638b18 = c2053t.m1638b(8) + 1;
                                for (int i34 = 0; i34 < m1638b18; i34++) {
                                    int i35 = i4 - 1;
                                    c2053t.m1639c(C4195m.m4825p0(i35));
                                    c2053t.m1639c(C4195m.m4825p0(i35));
                                }
                            }
                            if (c2053t.m1638b(2) != 0) {
                                throw new C2205l0("to reserved bits must be zero after mapping coupling steps");
                            }
                            if (m1638b17 > 1) {
                                for (int i36 = 0; i36 < i4; i36++) {
                                    c2053t.m1639c(4);
                                }
                            }
                            for (int i37 = 0; i37 < m1638b17; i37++) {
                                c2053t.m1639c(8);
                                c2053t.m1639c(8);
                                c2053t.m1639c(8);
                            }
                        }
                    }
                    int m1638b19 = c2053t.m1638b(6) + 1;
                    C2055v[] c2055vArr = new C2055v[m1638b19];
                    for (int i38 = 0; i38 < m1638b19; i38++) {
                        c2055vArr[i38] = new C2055v(c2053t.m1637a(), c2053t.m1638b(16), c2053t.m1638b(16), c2053t.m1638b(8));
                    }
                    if (!c2053t.m1637a()) {
                        throw new C2205l0("framing bit after modes not set as expected");
                    }
                    aVar = new a(this.f3780q, this.f3781r, bArr, c2055vArr, C4195m.m4825p0(m1638b19 - 1));
                }
            }
        }
        aVar = null;
        this.f3777n = aVar;
        if (aVar == null) {
            return true;
        }
        ArrayList arrayList = new ArrayList();
        arrayList.add(this.f3777n.f3782a.f4210f);
        arrayList.add(this.f3777n.f3783b);
        C2056w c2056w = this.f3777n.f3782a;
        bVar.f3775a = Format.m4024A(null, "audio/vorbis", null, c2056w.f4207c, -1, c2056w.f4205a, (int) c2056w.f4206b, arrayList, null, 0, null);
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p212d0.AbstractC2001h
    /* renamed from: e */
    public void mo1552e(boolean z) {
        super.mo1552e(z);
        if (z) {
            this.f3777n = null;
            this.f3780q = null;
            this.f3781r = null;
        }
        this.f3778o = 0;
        this.f3779p = false;
    }
}
