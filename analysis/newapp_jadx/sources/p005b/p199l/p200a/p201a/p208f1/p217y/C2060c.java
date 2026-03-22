package p005b.p199l.p200a.p201a.p208f1.p217y;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.flac.PictureFrame;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2044k;
import p005b.p199l.p200a.p201a.p208f1.C2045l;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2353m;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.y.c */
/* loaded from: classes.dex */
public final class C2060c implements InterfaceC2041h {

    /* renamed from: d */
    public InterfaceC2042i f4237d;

    /* renamed from: e */
    public InterfaceC2052s f4238e;

    /* renamed from: g */
    @Nullable
    public Metadata f4240g;

    /* renamed from: h */
    public C2353m f4241h;

    /* renamed from: i */
    public int f4242i;

    /* renamed from: j */
    public int f4243j;

    /* renamed from: k */
    public C2059b f4244k;

    /* renamed from: l */
    public int f4245l;

    /* renamed from: m */
    public long f4246m;

    /* renamed from: a */
    public final byte[] f4234a = new byte[42];

    /* renamed from: b */
    public final C2360t f4235b = new C2360t(new byte[32768], 0);

    /* renamed from: c */
    public final C2044k.a f4236c = new C2044k.a();

    /* renamed from: f */
    public int f4239f = 0;

    /* renamed from: a */
    public final void m1643a() {
        long j2 = this.f4246m * 1000000;
        C2353m c2353m = this.f4241h;
        int i2 = C2344d0.f6035a;
        this.f4238e.mo1614c(j2 / c2353m.f6077e, 1, this.f4245l, 0, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v13 */
    /* JADX WARN: Type inference failed for: r4v9, types: [boolean, int] */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        boolean z;
        C2353m c2353m;
        InterfaceC2050q bVar;
        long j2;
        boolean z2;
        int i2 = this.f4239f;
        ?? r4 = 0;
        if (i2 == 0) {
            c2003e.f3791f = 0;
            long m1564d = c2003e.m1564d();
            Metadata m4758B0 = C4195m.m4758B0(c2003e, true);
            c2003e.m1569i((int) (c2003e.m1564d() - m1564d));
            this.f4240g = m4758B0;
            this.f4239f = 1;
            return 0;
        }
        if (i2 == 1) {
            byte[] bArr = this.f4234a;
            c2003e.m1565e(bArr, 0, bArr.length, false);
            c2003e.f3791f = 0;
            this.f4239f = 2;
            return 0;
        }
        int i3 = 24;
        int i4 = 4;
        int i5 = 3;
        if (i2 == 2) {
            c2003e.m1568h(new byte[4], 0, 4, false);
            if ((((r8[0] & 255) << 24) | ((r8[1] & 255) << 16) | ((r8[2] & 255) << 8) | (r8[3] & 255)) != 1716281667) {
                throw new C2205l0("Failed to read FLAC stream marker.");
            }
            this.f4239f = 3;
            return 0;
        }
        if (i2 == 3) {
            C2353m c2353m2 = this.f4241h;
            boolean z3 = false;
            while (!z3) {
                c2003e.f3791f = r4;
                C2359s c2359s = new C2359s(new byte[i4]);
                c2003e.m1565e(c2359s.f6129a, r4, i4, r4);
                boolean m2557e = c2359s.m2557e();
                int m2558f = c2359s.m2558f(r11);
                int m2558f2 = c2359s.m2558f(i3) + i4;
                if (m2558f == 0) {
                    byte[] bArr2 = new byte[38];
                    c2003e.m1568h(bArr2, r4, 38, r4);
                    c2353m2 = new C2353m(bArr2, i4);
                } else {
                    if (c2353m2 == null) {
                        throw new IllegalArgumentException();
                    }
                    if (m2558f == i5) {
                        C2360t c2360t = new C2360t(m2558f2);
                        c2003e.m1568h(c2360t.f6133a, r4, m2558f2, r4);
                        c2353m2 = c2353m2.m2369b(C4195m.m4766F0(c2360t));
                    } else {
                        if (m2558f == i4) {
                            C2360t c2360t2 = new C2360t(m2558f2);
                            c2003e.m1568h(c2360t2.f6133a, r4, m2558f2, r4);
                            c2360t2.m2568D(i4);
                            c2353m = new C2353m(c2353m2.f6073a, c2353m2.f6074b, c2353m2.f6075c, c2353m2.f6076d, c2353m2.f6077e, c2353m2.f6079g, c2353m2.f6080h, c2353m2.f6082j, c2353m2.f6083k, c2353m2.m2372f(C2353m.m2366a(Arrays.asList(C4195m.m4768G0(c2360t2, r4, r4).f4203a), Collections.emptyList())));
                            z = m2557e;
                        } else if (m2558f == 6) {
                            C2360t c2360t3 = new C2360t(m2558f2);
                            c2003e.m1568h(c2360t3.f6133a, r4, m2558f2, r4);
                            c2360t3.m2568D(4);
                            int m2573e = c2360t3.m2573e();
                            String m2583o = c2360t3.m2583o(c2360t3.m2573e(), Charset.forName("US-ASCII"));
                            String m2582n = c2360t3.m2582n(c2360t3.m2573e());
                            int m2573e2 = c2360t3.m2573e();
                            int m2573e3 = c2360t3.m2573e();
                            int m2573e4 = c2360t3.m2573e();
                            int m2573e5 = c2360t3.m2573e();
                            int m2573e6 = c2360t3.m2573e();
                            byte[] bArr3 = new byte[m2573e6];
                            System.arraycopy(c2360t3.f6133a, c2360t3.f6134b, bArr3, r4, m2573e6);
                            c2360t3.f6134b += m2573e6;
                            z = m2557e;
                            c2353m = new C2353m(c2353m2.f6073a, c2353m2.f6074b, c2353m2.f6075c, c2353m2.f6076d, c2353m2.f6077e, c2353m2.f6079g, c2353m2.f6080h, c2353m2.f6082j, c2353m2.f6083k, c2353m2.m2372f(C2353m.m2366a(Collections.emptyList(), Collections.singletonList(new PictureFrame(m2573e, m2583o, m2582n, m2573e2, m2573e3, m2573e4, m2573e5, bArr3)))));
                        } else {
                            z = m2557e;
                            c2003e.m1569i(m2558f2);
                            int i6 = C2344d0.f6035a;
                            this.f4241h = c2353m2;
                            z3 = z;
                            r4 = 0;
                            i3 = 24;
                            i4 = 4;
                            i5 = 3;
                            r11 = 7;
                        }
                        c2353m2 = c2353m;
                        int i62 = C2344d0.f6035a;
                        this.f4241h = c2353m2;
                        z3 = z;
                        r4 = 0;
                        i3 = 24;
                        i4 = 4;
                        i5 = 3;
                        r11 = 7;
                    }
                }
                z = m2557e;
                int i622 = C2344d0.f6035a;
                this.f4241h = c2353m2;
                z3 = z;
                r4 = 0;
                i3 = 24;
                i4 = 4;
                i5 = 3;
                r11 = 7;
            }
            Objects.requireNonNull(this.f4241h);
            this.f4242i = Math.max(this.f4241h.f6075c, 6);
            InterfaceC2052s interfaceC2052s = this.f4238e;
            int i7 = C2344d0.f6035a;
            interfaceC2052s.mo1615d(this.f4241h.m2371e(this.f4234a, this.f4240g));
            this.f4239f = 4;
            return 0;
        }
        long j3 = 0;
        if (i2 == 4) {
            c2003e.f3791f = 0;
            byte[] bArr4 = new byte[2];
            c2003e.m1565e(bArr4, 0, 2, false);
            int i8 = (bArr4[1] & 255) | ((bArr4[0] & 255) << 8);
            if ((i8 >> 2) != 16382) {
                c2003e.f3791f = 0;
                throw new C2205l0("First frame does not start with sync code.");
            }
            c2003e.f3791f = 0;
            this.f4243j = i8;
            InterfaceC2042i interfaceC2042i = this.f4237d;
            int i9 = C2344d0.f6035a;
            long j4 = c2003e.f3789d;
            long j5 = c2003e.f3788c;
            Objects.requireNonNull(this.f4241h);
            C2353m c2353m3 = this.f4241h;
            if (c2353m3.f6083k != null) {
                bVar = new C2045l(c2353m3, j4);
            } else if (j5 == -1 || c2353m3.f6082j <= 0) {
                bVar = new InterfaceC2050q.b(c2353m3.m2370d(), 0L);
            } else {
                C2059b c2059b = new C2059b(c2353m3, this.f4243j, j4, j5);
                this.f4244k = c2059b;
                bVar = c2059b.f3395a;
            }
            interfaceC2042i.mo1623a(bVar);
            this.f4239f = 5;
            return 0;
        }
        if (i2 != 5) {
            throw new IllegalStateException();
        }
        Objects.requireNonNull(this.f4238e);
        Objects.requireNonNull(this.f4241h);
        C2059b c2059b2 = this.f4244k;
        if (c2059b2 != null && c2059b2.m1457b()) {
            return this.f4244k.m1456a(c2003e, c2049p);
        }
        if (this.f4246m == -1) {
            C2353m c2353m4 = this.f4241h;
            c2003e.f3791f = 0;
            c2003e.m1561a(1, false);
            byte[] bArr5 = new byte[1];
            c2003e.m1565e(bArr5, 0, 1, false);
            boolean z4 = (bArr5[0] & 1) == 1;
            c2003e.m1561a(2, false);
            r11 = z4 ? 7 : 6;
            C2360t c2360t4 = new C2360t(r11);
            c2360t4.m2566B(C4195m.m4760C0(c2003e, c2360t4.f6133a, 0, r11));
            c2003e.f3791f = 0;
            try {
                long m2591w = c2360t4.m2591w();
                if (!z4) {
                    m2591w *= c2353m4.f6074b;
                }
                j3 = m2591w;
            } catch (NumberFormatException unused) {
                r3 = false;
            }
            if (!r3) {
                throw new C2205l0();
            }
            this.f4246m = j3;
            return 0;
        }
        C2360t c2360t5 = this.f4235b;
        int i10 = c2360t5.f6135c;
        if (i10 < 32768) {
            int m1566f = c2003e.m1566f(c2360t5.f6133a, i10, 32768 - i10);
            r3 = m1566f == -1;
            if (!r3) {
                this.f4235b.m2566B(i10 + m1566f);
            } else if (this.f4235b.m2569a() == 0) {
                m1643a();
                return -1;
            }
        } else {
            r3 = false;
        }
        C2360t c2360t6 = this.f4235b;
        int i11 = c2360t6.f6134b;
        int i12 = this.f4245l;
        int i13 = this.f4242i;
        if (i12 < i13) {
            c2360t6.m2568D(Math.min(i13 - i12, c2360t6.m2569a()));
        }
        C2360t c2360t7 = this.f4235b;
        Objects.requireNonNull(this.f4241h);
        int i14 = c2360t7.f6134b;
        while (true) {
            if (i14 <= c2360t7.f6135c - 16) {
                c2360t7.m2567C(i14);
                if (C2044k.m1627b(c2360t7, this.f4241h, this.f4243j, this.f4236c)) {
                    c2360t7.m2567C(i14);
                    j2 = this.f4236c.f4166a;
                    break;
                }
                i14++;
            } else {
                if (r3) {
                    while (true) {
                        int i15 = c2360t7.f6135c;
                        if (i14 > i15 - this.f4242i) {
                            c2360t7.m2567C(i15);
                            break;
                        }
                        c2360t7.m2567C(i14);
                        try {
                            z2 = C2044k.m1627b(c2360t7, this.f4241h, this.f4243j, this.f4236c);
                        } catch (IndexOutOfBoundsException unused2) {
                            z2 = false;
                        }
                        if (c2360t7.f6134b > c2360t7.f6135c) {
                            z2 = false;
                        }
                        if (z2) {
                            c2360t7.m2567C(i14);
                            j2 = this.f4236c.f4166a;
                            break;
                        }
                        i14++;
                    }
                } else {
                    c2360t7.m2567C(i14);
                }
                j2 = -1;
            }
        }
        C2360t c2360t8 = this.f4235b;
        int i16 = c2360t8.f6134b - i11;
        c2360t8.m2567C(i11);
        this.f4238e.mo1613b(this.f4235b, i16);
        this.f4245l += i16;
        if (j2 != -1) {
            m1643a();
            this.f4245l = 0;
            this.f4246m = j2;
        }
        if (this.f4235b.m2569a() >= 16) {
            return 0;
        }
        C2360t c2360t9 = this.f4235b;
        byte[] bArr6 = c2360t9.f6133a;
        System.arraycopy(bArr6, c2360t9.f6134b, bArr6, 0, c2360t9.m2569a());
        C2360t c2360t10 = this.f4235b;
        c2360t10.m2593y(c2360t10.m2569a());
        return 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f4237d = interfaceC2042i;
        this.f4238e = interfaceC2042i.mo1625t(0, 1);
        interfaceC2042i.mo1624o();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        if (j2 == 0) {
            this.f4239f = 0;
        } else {
            C2059b c2059b = this.f4244k;
            if (c2059b != null) {
                c2059b.m1460e(j3);
            }
        }
        this.f4246m = j3 != 0 ? -1L : 0L;
        this.f4245l = 0;
        this.f4235b.m2592x();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        C4195m.m4758B0(c2003e, false);
        byte[] bArr = new byte[4];
        c2003e.m1565e(bArr, 0, 4, false);
        return (((((((long) bArr[0]) & 255) << 24) | ((((long) bArr[1]) & 255) << 16)) | ((((long) bArr[2]) & 255) << 8)) | (255 & ((long) bArr[3]))) == 1716281667;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
