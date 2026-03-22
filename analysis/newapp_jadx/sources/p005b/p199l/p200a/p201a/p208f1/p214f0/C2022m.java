package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import java.util.Collections;
import kotlin.jvm.internal.ByteCompanionObject;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p005b.p199l.p200a.p201a.p250p1.C2361u;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.m */
/* loaded from: classes.dex */
public final class C2022m implements InterfaceC2019j {

    /* renamed from: a */
    public final C2033x f4001a;

    /* renamed from: b */
    public String f4002b;

    /* renamed from: c */
    public InterfaceC2052s f4003c;

    /* renamed from: d */
    public a f4004d;

    /* renamed from: e */
    public boolean f4005e;

    /* renamed from: l */
    public long f4012l;

    /* renamed from: m */
    public long f4013m;

    /* renamed from: f */
    public final boolean[] f4006f = new boolean[3];

    /* renamed from: g */
    public final C2026q f4007g = new C2026q(32, 128);

    /* renamed from: h */
    public final C2026q f4008h = new C2026q(33, 128);

    /* renamed from: i */
    public final C2026q f4009i = new C2026q(34, 128);

    /* renamed from: j */
    public final C2026q f4010j = new C2026q(39, 128);

    /* renamed from: k */
    public final C2026q f4011k = new C2026q(40, 128);

    /* renamed from: n */
    public final C2360t f4014n = new C2360t();

    /* renamed from: b.l.a.a.f1.f0.m$a */
    public static final class a {

        /* renamed from: a */
        public final InterfaceC2052s f4015a;

        /* renamed from: b */
        public long f4016b;

        /* renamed from: c */
        public boolean f4017c;

        /* renamed from: d */
        public int f4018d;

        /* renamed from: e */
        public long f4019e;

        /* renamed from: f */
        public boolean f4020f;

        /* renamed from: g */
        public boolean f4021g;

        /* renamed from: h */
        public boolean f4022h;

        /* renamed from: i */
        public boolean f4023i;

        /* renamed from: j */
        public boolean f4024j;

        /* renamed from: k */
        public long f4025k;

        /* renamed from: l */
        public long f4026l;

        /* renamed from: m */
        public boolean f4027m;

        public a(InterfaceC2052s interfaceC2052s) {
            this.f4015a = interfaceC2052s;
        }

        /* renamed from: a */
        public final void m1598a(int i2) {
            boolean z = this.f4027m;
            this.f4015a.mo1614c(this.f4026l, z ? 1 : 0, (int) (this.f4016b - this.f4025k), i2, null);
        }
    }

    public C2022m(C2033x c2033x) {
        this.f4001a = c2033x;
    }

    /* renamed from: a */
    public final void m1597a(byte[] bArr, int i2, int i3) {
        if (this.f4005e) {
            a aVar = this.f4004d;
            if (aVar.f4020f) {
                int i4 = aVar.f4018d;
                int i5 = (i2 + 2) - i4;
                if (i5 < i3) {
                    aVar.f4021g = (bArr[i5] & ByteCompanionObject.MIN_VALUE) != 0;
                    aVar.f4020f = false;
                } else {
                    aVar.f4018d = (i3 - i2) + i4;
                }
            }
        } else {
            this.f4007g.m1601a(bArr, i2, i3);
            this.f4008h.m1601a(bArr, i2, i3);
            this.f4009i.m1601a(bArr, i2, i3);
        }
        this.f4010j.m1601a(bArr, i2, i3);
        this.f4011k.m1601a(bArr, i2, i3);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    public void mo1573b(C2360t c2360t) {
        int i2;
        int i3;
        byte[] bArr;
        int i4;
        int i5;
        int i6;
        long j2;
        float f2;
        int i7;
        long j3;
        int i8;
        while (c2360t.m2569a() > 0) {
            int i9 = c2360t.f6135c;
            byte[] bArr2 = c2360t.f6133a;
            this.f4012l += c2360t.m2569a();
            this.f4003c.mo1613b(c2360t, c2360t.m2569a());
            for (int i10 = c2360t.f6134b; i10 < i9; i10 = i4) {
                int m2549b = C2358r.m2549b(bArr2, i10, i9, this.f4006f);
                if (m2549b == i9) {
                    m1597a(bArr2, i10, i9);
                    return;
                }
                int i11 = m2549b + 3;
                int i12 = (bArr2[i11] & 126) >> 1;
                int i13 = m2549b - i10;
                if (i13 > 0) {
                    m1597a(bArr2, i10, m2549b);
                }
                int i14 = i9 - m2549b;
                long j4 = this.f4012l - i14;
                int i15 = i13 < 0 ? -i13 : 0;
                long j5 = this.f4013m;
                if (this.f4005e) {
                    a aVar = this.f4004d;
                    if (aVar.f4024j && aVar.f4021g) {
                        aVar.f4027m = aVar.f4017c;
                        aVar.f4024j = false;
                    } else if (aVar.f4022h || aVar.f4021g) {
                        if (aVar.f4023i) {
                            i2 = i11;
                            aVar.m1598a(((int) (j4 - aVar.f4016b)) + i14);
                        } else {
                            i2 = i11;
                        }
                        aVar.f4025k = aVar.f4016b;
                        aVar.f4026l = aVar.f4019e;
                        aVar.f4023i = true;
                        aVar.f4027m = aVar.f4017c;
                        i5 = i14;
                        i3 = i9;
                        bArr = bArr2;
                        i6 = i12;
                        j2 = j4;
                        i4 = i2;
                    }
                    i5 = i14;
                    i3 = i9;
                    bArr = bArr2;
                    i4 = i11;
                    i6 = i12;
                    j2 = j4;
                } else {
                    i2 = i11;
                    this.f4007g.m1602b(i15);
                    this.f4008h.m1602b(i15);
                    this.f4009i.m1602b(i15);
                    C2026q c2026q = this.f4007g;
                    if (c2026q.f4068c) {
                        C2026q c2026q2 = this.f4008h;
                        if (c2026q2.f4068c) {
                            C2026q c2026q3 = this.f4009i;
                            if (c2026q3.f4068c) {
                                InterfaceC2052s interfaceC2052s = this.f4003c;
                                String str = this.f4002b;
                                i3 = i9;
                                int i16 = c2026q.f4070e;
                                bArr = bArr2;
                                i4 = i2;
                                byte[] bArr3 = new byte[c2026q2.f4070e + i16 + c2026q3.f4070e];
                                i5 = i14;
                                System.arraycopy(c2026q.f4069d, 0, bArr3, 0, i16);
                                i6 = i12;
                                System.arraycopy(c2026q2.f4069d, 0, bArr3, c2026q.f4070e, c2026q2.f4070e);
                                System.arraycopy(c2026q3.f4069d, 0, bArr3, c2026q.f4070e + c2026q2.f4070e, c2026q3.f4070e);
                                C2361u c2361u = new C2361u(c2026q2.f4069d, 0, c2026q2.f4070e);
                                c2361u.m2604j(44);
                                int m2599e = c2361u.m2599e(3);
                                c2361u.m2603i();
                                c2361u.m2604j(88);
                                c2361u.m2604j(8);
                                int i17 = 0;
                                for (int i18 = 0; i18 < m2599e; i18++) {
                                    if (c2361u.m2598d()) {
                                        i17 += 89;
                                    }
                                    if (c2361u.m2598d()) {
                                        i17 += 8;
                                    }
                                }
                                c2361u.m2604j(i17);
                                if (m2599e > 0) {
                                    c2361u.m2604j((8 - m2599e) * 2);
                                }
                                c2361u.m2600f();
                                int m2600f = c2361u.m2600f();
                                if (m2600f == 3) {
                                    c2361u.m2603i();
                                }
                                int m2600f2 = c2361u.m2600f();
                                int m2600f3 = c2361u.m2600f();
                                if (c2361u.m2598d()) {
                                    int m2600f4 = c2361u.m2600f();
                                    int m2600f5 = c2361u.m2600f();
                                    int m2600f6 = c2361u.m2600f();
                                    int m2600f7 = c2361u.m2600f();
                                    m2600f2 -= (m2600f4 + m2600f5) * ((m2600f == 1 || m2600f == 2) ? 2 : 1);
                                    m2600f3 -= (m2600f6 + m2600f7) * (m2600f == 1 ? 2 : 1);
                                }
                                int i19 = m2600f3;
                                c2361u.m2600f();
                                c2361u.m2600f();
                                int m2600f8 = c2361u.m2600f();
                                for (int i20 = c2361u.m2598d() ? 0 : m2599e; i20 <= m2599e; i20++) {
                                    c2361u.m2600f();
                                    c2361u.m2600f();
                                    c2361u.m2600f();
                                }
                                c2361u.m2600f();
                                c2361u.m2600f();
                                c2361u.m2600f();
                                c2361u.m2600f();
                                c2361u.m2600f();
                                c2361u.m2600f();
                                if (c2361u.m2598d() && c2361u.m2598d()) {
                                    int i21 = 0;
                                    for (int i22 = 4; i21 < i22; i22 = 4) {
                                        int i23 = 0;
                                        while (i23 < 6) {
                                            if (c2361u.m2598d()) {
                                                j3 = j4;
                                                int min = Math.min(64, 1 << ((i21 << 1) + 4));
                                                if (i21 > 1) {
                                                    c2361u.m2601g();
                                                }
                                                for (int i24 = 0; i24 < min; i24++) {
                                                    c2361u.m2601g();
                                                }
                                            } else {
                                                c2361u.m2600f();
                                                j3 = j4;
                                            }
                                            i23 += i21 == 3 ? 3 : 1;
                                            j4 = j3;
                                        }
                                        i21++;
                                    }
                                }
                                j2 = j4;
                                c2361u.m2604j(2);
                                if (c2361u.m2598d()) {
                                    c2361u.m2604j(8);
                                    c2361u.m2600f();
                                    c2361u.m2600f();
                                    c2361u.m2603i();
                                }
                                int m2600f9 = c2361u.m2600f();
                                int i25 = 0;
                                boolean z = false;
                                int i26 = 0;
                                while (i25 < m2600f9) {
                                    if (i25 != 0) {
                                        z = c2361u.m2598d();
                                    }
                                    if (z) {
                                        c2361u.m2603i();
                                        c2361u.m2600f();
                                        for (int i27 = 0; i27 <= i26; i27++) {
                                            if (c2361u.m2598d()) {
                                                c2361u.m2603i();
                                            }
                                        }
                                        i7 = m2600f9;
                                    } else {
                                        int m2600f10 = c2361u.m2600f();
                                        int m2600f11 = c2361u.m2600f();
                                        int i28 = m2600f10 + m2600f11;
                                        i7 = m2600f9;
                                        for (int i29 = 0; i29 < m2600f10; i29++) {
                                            c2361u.m2600f();
                                            c2361u.m2603i();
                                        }
                                        for (int i30 = 0; i30 < m2600f11; i30++) {
                                            c2361u.m2600f();
                                            c2361u.m2603i();
                                        }
                                        i26 = i28;
                                    }
                                    i25++;
                                    m2600f9 = i7;
                                }
                                if (c2361u.m2598d()) {
                                    for (int i31 = 0; i31 < c2361u.m2600f(); i31++) {
                                        c2361u.m2604j(m2600f8 + 4 + 1);
                                    }
                                }
                                c2361u.m2604j(2);
                                float f3 = 1.0f;
                                if (c2361u.m2598d() && c2361u.m2598d()) {
                                    int m2599e2 = c2361u.m2599e(8);
                                    if (m2599e2 == 255) {
                                        int m2599e3 = c2361u.m2599e(16);
                                        int m2599e4 = c2361u.m2599e(16);
                                        if (m2599e3 != 0 && m2599e4 != 0) {
                                            f3 = m2599e3 / m2599e4;
                                        }
                                        f2 = f3;
                                    } else {
                                        float[] fArr = C2358r.f6110b;
                                        if (m2599e2 < fArr.length) {
                                            f2 = fArr[m2599e2];
                                        }
                                    }
                                    interfaceC2052s.mo1615d(Format.m4034K(str, "video/hevc", null, -1, -1, m2600f2, i19, -1.0f, Collections.singletonList(bArr3), -1, f2, null));
                                    this.f4005e = true;
                                }
                                f2 = 1.0f;
                                interfaceC2052s.mo1615d(Format.m4034K(str, "video/hevc", null, -1, -1, m2600f2, i19, -1.0f, Collections.singletonList(bArr3), -1, f2, null));
                                this.f4005e = true;
                            }
                        }
                    }
                    i5 = i14;
                    i3 = i9;
                    bArr = bArr2;
                    i6 = i12;
                    j2 = j4;
                    i4 = i2;
                }
                if (this.f4010j.m1602b(i15)) {
                    C2026q c2026q4 = this.f4010j;
                    this.f4014n.m2565A(this.f4010j.f4069d, C2358r.m2552e(c2026q4.f4069d, c2026q4.f4070e));
                    this.f4014n.m2568D(5);
                    C4195m.m4781N(j5, this.f4014n, this.f4001a.f4119b);
                }
                if (this.f4011k.m1602b(i15)) {
                    C2026q c2026q5 = this.f4011k;
                    this.f4014n.m2565A(this.f4011k.f4069d, C2358r.m2552e(c2026q5.f4069d, c2026q5.f4070e));
                    this.f4014n.m2568D(5);
                    C4195m.m4781N(j5, this.f4014n, this.f4001a.f4119b);
                }
                long j6 = this.f4013m;
                if (this.f4005e) {
                    a aVar2 = this.f4004d;
                    aVar2.f4021g = false;
                    aVar2.f4022h = false;
                    aVar2.f4019e = j6;
                    aVar2.f4018d = 0;
                    aVar2.f4016b = j2;
                    i8 = i6;
                    if (i8 >= 32) {
                        if (!aVar2.f4024j && aVar2.f4023i) {
                            aVar2.m1598a(i5);
                            aVar2.f4023i = false;
                        }
                        if (i8 <= 34) {
                            aVar2.f4022h = !aVar2.f4024j;
                            aVar2.f4024j = true;
                            boolean z2 = i8 < 16 && i8 <= 21;
                            aVar2.f4017c = z2;
                            aVar2.f4020f = !z2 || i8 <= 9;
                        }
                    }
                    if (i8 < 16) {
                    }
                    aVar2.f4017c = z2;
                    aVar2.f4020f = !z2 || i8 <= 9;
                } else {
                    i8 = i6;
                    this.f4007g.m1604d(i8);
                    this.f4008h.m1604d(i8);
                    this.f4009i.m1604d(i8);
                }
                this.f4010j.m1604d(i8);
                this.f4011k.m1604d(i8);
                i9 = i3;
                bArr2 = bArr;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        C2358r.m2548a(this.f4006f);
        this.f4007g.m1603c();
        this.f4008h.m1603c();
        this.f4009i.m1603c();
        this.f4010j.m1603c();
        this.f4011k.m1603c();
        a aVar = this.f4004d;
        aVar.f4020f = false;
        aVar.f4021g = false;
        aVar.f4022h = false;
        aVar.f4023i = false;
        aVar.f4024j = false;
        this.f4012l = 0L;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        dVar.m1584a();
        this.f4002b = dVar.m1585b();
        InterfaceC2052s mo1625t = interfaceC2042i.mo1625t(dVar.m1586c(), 2);
        this.f4003c = mo1625t;
        this.f4004d = new a(mo1625t);
        this.f4001a.m1611a(interfaceC2042i, dVar);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        this.f4013m = j2;
    }
}
