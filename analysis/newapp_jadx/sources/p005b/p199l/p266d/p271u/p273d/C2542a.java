package p005b.p199l.p266d.p271u.p273d;

import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.p271u.C2539a;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p274v.C2548f;
import p005b.p199l.p266d.p274v.C2552j;
import p005b.p199l.p266d.p274v.p275l.C2554a;
import p005b.p199l.p266d.p274v.p276m.C2555a;
import p005b.p199l.p266d.p274v.p276m.C2557c;
import p005b.p199l.p266d.p274v.p276m.C2559e;

/* renamed from: b.l.d.u.d.a */
/* loaded from: classes2.dex */
public final class C2542a {

    /* renamed from: a */
    public static final int[] f6882a = {3808, 476, 2107, 1799};

    /* renamed from: b */
    public final C2544b f6883b;

    /* renamed from: c */
    public boolean f6884c;

    /* renamed from: d */
    public int f6885d;

    /* renamed from: e */
    public int f6886e;

    /* renamed from: f */
    public int f6887f;

    /* renamed from: g */
    public int f6888g;

    /* renamed from: b.l.d.u.d.a$a */
    public static final class a {

        /* renamed from: a */
        public final int f6889a;

        /* renamed from: b */
        public final int f6890b;

        public a(int i2, int i3) {
            this.f6889a = i2;
            this.f6890b = i3;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder("<");
            sb.append(this.f6889a);
            sb.append(' ');
            return C1499a.m579A(sb, this.f6890b, Typography.greater);
        }
    }

    public C2542a(C2544b c2544b) {
        this.f6883b = c2544b;
    }

    /* renamed from: b */
    public static C2536r[] m2938b(C2536r[] c2536rArr, int i2, int i3) {
        float f2 = i3 / (i2 * 2.0f);
        float f3 = c2536rArr[0].f6871a - c2536rArr[2].f6871a;
        float f4 = c2536rArr[0].f6872b - c2536rArr[2].f6872b;
        float f5 = (c2536rArr[0].f6871a + c2536rArr[2].f6871a) / 2.0f;
        float f6 = (c2536rArr[0].f6872b + c2536rArr[2].f6872b) / 2.0f;
        float f7 = f3 * f2;
        float f8 = f4 * f2;
        C2536r c2536r = new C2536r(f5 + f7, f6 + f8);
        C2536r c2536r2 = new C2536r(f5 - f7, f6 - f8);
        float f9 = c2536rArr[1].f6871a - c2536rArr[3].f6871a;
        float f10 = c2536rArr[1].f6872b - c2536rArr[3].f6872b;
        float f11 = (c2536rArr[1].f6871a + c2536rArr[3].f6871a) / 2.0f;
        float f12 = (c2536rArr[1].f6872b + c2536rArr[3].f6872b) / 2.0f;
        float f13 = f9 * f2;
        float f14 = f2 * f10;
        return new C2536r[]{c2536r, new C2536r(f11 + f13, f12 + f14), c2536r2, new C2536r(f11 - f13, f12 - f14)};
    }

    /* renamed from: a */
    public C2539a m2939a(boolean z) {
        C2536r c2536r;
        C2536r c2536r2;
        C2536r c2536r3;
        C2536r c2536r4;
        C2536r c2536r5;
        C2536r c2536r6;
        C2536r c2536r7;
        C2536r c2536r8;
        int i2;
        long j2;
        int i3;
        a aVar;
        int i4 = 2;
        int i5 = -1;
        int i6 = 1;
        try {
            C2544b c2544b = this.f6883b;
            C2536r[] m2973b = new C2554a(c2544b, 10, c2544b.f6893c / 2, c2544b.f6894e / 2).m2973b();
            c2536r4 = m2973b[0];
            c2536r3 = m2973b[1];
            c2536r2 = m2973b[2];
            c2536r = m2973b[3];
        } catch (C2529k unused) {
            C2544b c2544b2 = this.f6883b;
            int i7 = c2544b2.f6893c / 2;
            int i8 = c2544b2.f6894e / 2;
            int i9 = i8 - 7;
            int i10 = i7 + 7 + 1;
            int i11 = i10;
            int i12 = i9;
            while (true) {
                i12--;
                if (!m2943f(i11, i12) || this.f6883b.m2958c(i11, i12)) {
                    break;
                }
                i11++;
            }
            int i13 = i11 - 1;
            int i14 = i12 + 1;
            while (m2943f(i13, i14) && !this.f6883b.m2958c(i13, i14)) {
                i13++;
            }
            int i15 = i13 - 1;
            while (m2943f(i15, i14) && !this.f6883b.m2958c(i15, i14)) {
                i14--;
            }
            C2536r c2536r9 = new C2536r(i15, i14 + 1);
            int i16 = i8 + 7;
            int i17 = i16;
            while (true) {
                i17++;
                if (!m2943f(i10, i17) || this.f6883b.m2958c(i10, i17)) {
                    break;
                }
                i10++;
            }
            int i18 = i10 - 1;
            int i19 = i17 - 1;
            while (m2943f(i18, i19) && !this.f6883b.m2958c(i18, i19)) {
                i18++;
            }
            int i20 = i18 - 1;
            while (m2943f(i20, i19) && !this.f6883b.m2958c(i20, i19)) {
                i19++;
            }
            C2536r c2536r10 = new C2536r(i20, i19 - 1);
            int i21 = i7 - 7;
            int i22 = i21 - 1;
            while (true) {
                i16++;
                if (!m2943f(i22, i16) || this.f6883b.m2958c(i22, i16)) {
                    break;
                }
                i22--;
            }
            int i23 = i22 + 1;
            int i24 = i16 - 1;
            while (m2943f(i23, i24) && !this.f6883b.m2958c(i23, i24)) {
                i23--;
            }
            int i25 = i23 + 1;
            while (m2943f(i25, i24) && !this.f6883b.m2958c(i25, i24)) {
                i24++;
            }
            C2536r c2536r11 = new C2536r(i25, i24 - 1);
            do {
                i21--;
                i9--;
                if (!m2943f(i21, i9)) {
                    break;
                }
            } while (!this.f6883b.m2958c(i21, i9));
            int i26 = i21 + 1;
            int i27 = i9 + 1;
            while (m2943f(i26, i27) && !this.f6883b.m2958c(i26, i27)) {
                i26--;
            }
            int i28 = i26 + 1;
            while (m2943f(i28, i27) && !this.f6883b.m2958c(i28, i27)) {
                i27--;
            }
            c2536r = new C2536r(i28, i27 + 1);
            c2536r2 = c2536r11;
            c2536r3 = c2536r10;
            c2536r4 = c2536r9;
        }
        int m2520u1 = C2354n.m2520u1((((c2536r4.f6871a + c2536r.f6871a) + c2536r3.f6871a) + c2536r2.f6871a) / 4.0f);
        int m2520u12 = C2354n.m2520u1((((c2536r4.f6872b + c2536r.f6872b) + c2536r3.f6872b) + c2536r2.f6872b) / 4.0f);
        try {
            C2536r[] m2973b2 = new C2554a(this.f6883b, 15, m2520u1, m2520u12).m2973b();
            c2536r6 = m2973b2[0];
            c2536r8 = m2973b2[1];
            c2536r7 = m2973b2[2];
            c2536r5 = m2973b2[3];
        } catch (C2529k unused2) {
            int i29 = m2520u12 - 7;
            int i30 = m2520u1 + 7 + 1;
            int i31 = i30;
            int i32 = i29;
            while (true) {
                i32--;
                if (!m2943f(i31, i32) || this.f6883b.m2958c(i31, i32)) {
                    break;
                }
                i31++;
            }
            int i33 = i31 - 1;
            int i34 = i32 + 1;
            while (m2943f(i33, i34) && !this.f6883b.m2958c(i33, i34)) {
                i33++;
            }
            int i35 = i33 - 1;
            while (m2943f(i35, i34) && !this.f6883b.m2958c(i35, i34)) {
                i34--;
            }
            C2536r c2536r12 = new C2536r(i35, i34 + 1);
            int i36 = m2520u12 + 7;
            int i37 = i36;
            while (true) {
                i37++;
                if (!m2943f(i30, i37) || this.f6883b.m2958c(i30, i37)) {
                    break;
                }
                i30++;
            }
            int i38 = i30 - 1;
            int i39 = i37 - 1;
            while (m2943f(i38, i39) && !this.f6883b.m2958c(i38, i39)) {
                i38++;
            }
            int i40 = i38 - 1;
            while (m2943f(i40, i39) && !this.f6883b.m2958c(i40, i39)) {
                i39++;
            }
            C2536r c2536r13 = new C2536r(i40, i39 - 1);
            int i41 = m2520u1 - 7;
            int i42 = i41 - 1;
            while (true) {
                i36++;
                if (!m2943f(i42, i36) || this.f6883b.m2958c(i42, i36)) {
                    break;
                }
                i42--;
            }
            int i43 = i42 + 1;
            int i44 = i36 - 1;
            while (m2943f(i43, i44) && !this.f6883b.m2958c(i43, i44)) {
                i43--;
            }
            int i45 = i43 + 1;
            while (m2943f(i45, i44) && !this.f6883b.m2958c(i45, i44)) {
                i44++;
            }
            C2536r c2536r14 = new C2536r(i45, i44 - 1);
            do {
                i41--;
                i29--;
                if (!m2943f(i41, i29)) {
                    break;
                }
            } while (!this.f6883b.m2958c(i41, i29));
            int i46 = i41 + 1;
            int i47 = i29 + 1;
            while (m2943f(i46, i47) && !this.f6883b.m2958c(i46, i47)) {
                i46--;
            }
            int i48 = i46 + 1;
            while (m2943f(i48, i47) && !this.f6883b.m2958c(i48, i47)) {
                i47--;
            }
            c2536r5 = new C2536r(i48, i47 + 1);
            c2536r6 = c2536r12;
            c2536r7 = c2536r14;
            c2536r8 = c2536r13;
        }
        a aVar2 = new a(C2354n.m2520u1((((c2536r6.f6871a + c2536r5.f6871a) + c2536r8.f6871a) + c2536r7.f6871a) / 4.0f), C2354n.m2520u1((((c2536r6.f6872b + c2536r5.f6872b) + c2536r8.f6872b) + c2536r7.f6872b) / 4.0f));
        this.f6887f = 1;
        a aVar3 = aVar2;
        a aVar4 = aVar3;
        a aVar5 = aVar4;
        boolean z2 = true;
        while (this.f6887f < 9) {
            a m2942e = m2942e(aVar2, z2, i6, i5);
            a m2942e2 = m2942e(aVar3, z2, i6, i6);
            a m2942e3 = m2942e(aVar4, z2, i5, i6);
            a m2942e4 = m2942e(aVar5, z2, i5, i5);
            if (this.f6887f > i4) {
                double m2431T = (C2354n.m2431T(m2942e4.f6889a, m2942e4.f6890b, m2942e.f6889a, m2942e.f6890b) * this.f6887f) / (C2354n.m2431T(aVar5.f6889a, aVar5.f6890b, aVar2.f6889a, aVar2.f6890b) * (this.f6887f + i4));
                if (m2431T < 0.75d || m2431T > 1.25d) {
                    break;
                }
                a aVar6 = new a(m2942e.f6889a - 3, m2942e.f6890b + 3);
                a aVar7 = new a(m2942e2.f6889a - 3, m2942e2.f6890b - 3);
                a aVar8 = new a(m2942e3.f6889a + 3, m2942e3.f6890b - 3);
                aVar = m2942e;
                a aVar9 = new a(m2942e4.f6889a + 3, m2942e4.f6890b + 3);
                int m2940c = m2940c(aVar9, aVar6);
                if (!(m2940c != 0 && m2940c(aVar6, aVar7) == m2940c && m2940c(aVar7, aVar8) == m2940c && m2940c(aVar8, aVar9) == m2940c)) {
                    break;
                }
            } else {
                aVar = m2942e;
            }
            z2 = !z2;
            this.f6887f++;
            aVar5 = m2942e4;
            aVar3 = m2942e2;
            aVar4 = m2942e3;
            aVar2 = aVar;
            i4 = 2;
            i5 = -1;
            i6 = 1;
        }
        int i49 = this.f6887f;
        if (i49 != 5 && i49 != 7) {
            throw C2529k.f6843f;
        }
        this.f6884c = i49 == 5;
        int i50 = i49 * 2;
        C2536r[] m2938b = m2938b(new C2536r[]{new C2536r(aVar2.f6889a + 0.5f, aVar2.f6890b - 0.5f), new C2536r(aVar3.f6889a + 0.5f, aVar3.f6890b + 0.5f), new C2536r(aVar4.f6889a - 0.5f, aVar4.f6890b + 0.5f), new C2536r(aVar5.f6889a - 0.5f, aVar5.f6890b - 0.5f)}, i50 - 3, i50);
        if (z) {
            C2536r c2536r15 = m2938b[0];
            m2938b[0] = m2938b[2];
            m2938b[2] = c2536r15;
        }
        if (!m2944g(m2938b[0]) || !m2944g(m2938b[1]) || !m2944g(m2938b[2]) || !m2944g(m2938b[3])) {
            throw C2529k.f6843f;
        }
        int i51 = this.f6887f * 2;
        int[] iArr = {m2945h(m2938b[0], m2938b[1], i51), m2945h(m2938b[1], m2938b[2], i51), m2945h(m2938b[2], m2938b[3], i51), m2945h(m2938b[3], m2938b[0], i51)};
        int i52 = 0;
        for (int i53 = 0; i53 < 4; i53++) {
            int i54 = iArr[i53];
            i52 = (i52 << 3) + ((i54 >> (i51 - 2)) << 1) + (i54 & 1);
        }
        int i55 = ((i52 & 1) << 11) + (i52 >> 1);
        for (int i56 = 0; i56 < 4; i56++) {
            if (Integer.bitCount(f6882a[i56] ^ i55) <= 2) {
                this.f6888g = i56;
                long j3 = 0;
                for (int i57 = 0; i57 < 4; i57++) {
                    int i58 = iArr[(this.f6888g + i57) % 4];
                    if (this.f6884c) {
                        j2 = j3 << 7;
                        i3 = (i58 >> 1) & 127;
                    } else {
                        j2 = j3 << 10;
                        i3 = ((i58 >> 1) & 31) + ((i58 >> 2) & 992);
                    }
                    j3 = j2 + i3;
                }
                int i59 = 7;
                if (this.f6884c) {
                    i2 = 2;
                } else {
                    i2 = 4;
                    i59 = 10;
                }
                int i60 = i59 - i2;
                int[] iArr2 = new int[i59];
                while (true) {
                    i59--;
                    if (i59 < 0) {
                        try {
                            break;
                        } catch (C2559e unused3) {
                            throw C2529k.f6843f;
                        }
                    }
                    iArr2[i59] = ((int) j3) & 15;
                    j3 >>= 4;
                }
                new C2557c(C2555a.f6968d).m2986a(iArr2, i60);
                int i61 = 0;
                for (int i62 = 0; i62 < i2; i62++) {
                    i61 = (i61 << 4) + iArr2[i62];
                }
                if (this.f6884c) {
                    this.f6885d = (i61 >> 6) + 1;
                    this.f6886e = (i61 & 63) + 1;
                } else {
                    this.f6885d = (i61 >> 11) + 1;
                    this.f6886e = (i61 & 2047) + 1;
                }
                C2544b c2544b3 = this.f6883b;
                int i63 = this.f6888g;
                C2536r c2536r16 = m2938b[i63 % 4];
                C2536r c2536r17 = m2938b[(i63 + 1) % 4];
                C2536r c2536r18 = m2938b[(i63 + 2) % 4];
                C2536r c2536r19 = m2938b[(i63 + 3) % 4];
                C2548f c2548f = C2548f.f6940a;
                int m2941d = m2941d();
                float f2 = m2941d / 2.0f;
                float f3 = this.f6887f;
                float f4 = f2 - f3;
                float f5 = f2 + f3;
                return new C2539a(c2548f.m2967a(c2544b3, m2941d, m2941d, C2552j.m2970a(f4, f4, f5, f4, f5, f5, f4, f5, c2536r16.f6871a, c2536r16.f6872b, c2536r17.f6871a, c2536r17.f6872b, c2536r18.f6871a, c2536r18.f6872b, c2536r19.f6871a, c2536r19.f6872b)), m2938b(m2938b, this.f6887f * 2, m2941d()), this.f6884c, this.f6886e, this.f6885d);
            }
        }
        throw C2529k.f6843f;
    }

    /* renamed from: c */
    public final int m2940c(a aVar, a aVar2) {
        float m2431T = C2354n.m2431T(aVar.f6889a, aVar.f6890b, aVar2.f6889a, aVar2.f6890b);
        int i2 = aVar2.f6889a;
        int i3 = aVar.f6889a;
        float f2 = (i2 - i3) / m2431T;
        int i4 = aVar2.f6890b;
        int i5 = aVar.f6890b;
        float f3 = (i4 - i5) / m2431T;
        float f4 = i3;
        float f5 = i5;
        boolean m2958c = this.f6883b.m2958c(i3, i5);
        int ceil = (int) Math.ceil(m2431T);
        int i6 = 0;
        for (int i7 = 0; i7 < ceil; i7++) {
            f4 += f2;
            f5 += f3;
            if (this.f6883b.m2958c(C2354n.m2520u1(f4), C2354n.m2520u1(f5)) != m2958c) {
                i6++;
            }
        }
        float f6 = i6 / m2431T;
        if (f6 <= 0.1f || f6 >= 0.9f) {
            return (f6 <= 0.1f) == m2958c ? 1 : -1;
        }
        return 0;
    }

    /* renamed from: d */
    public final int m2941d() {
        if (this.f6884c) {
            return (this.f6885d * 4) + 11;
        }
        int i2 = this.f6885d;
        if (i2 <= 4) {
            return (i2 * 4) + 15;
        }
        return ((((i2 - 4) / 8) + 1) * 2) + (i2 * 4) + 15;
    }

    /* renamed from: e */
    public final a m2942e(a aVar, boolean z, int i2, int i3) {
        int i4 = aVar.f6889a + i2;
        int i5 = aVar.f6890b;
        while (true) {
            i5 += i3;
            if (!m2943f(i4, i5) || this.f6883b.m2958c(i4, i5) != z) {
                break;
            }
            i4 += i2;
        }
        int i6 = i4 - i2;
        int i7 = i5 - i3;
        while (m2943f(i6, i7) && this.f6883b.m2958c(i6, i7) == z) {
            i6 += i2;
        }
        int i8 = i6 - i2;
        while (m2943f(i8, i7) && this.f6883b.m2958c(i8, i7) == z) {
            i7 += i3;
        }
        return new a(i8, i7 - i3);
    }

    /* renamed from: f */
    public final boolean m2943f(int i2, int i3) {
        if (i2 < 0) {
            return false;
        }
        C2544b c2544b = this.f6883b;
        return i2 < c2544b.f6893c && i3 > 0 && i3 < c2544b.f6894e;
    }

    /* renamed from: g */
    public final boolean m2944g(C2536r c2536r) {
        return m2943f(C2354n.m2520u1(c2536r.f6871a), C2354n.m2520u1(c2536r.f6872b));
    }

    /* renamed from: h */
    public final int m2945h(C2536r c2536r, C2536r c2536r2, int i2) {
        float m2428S = C2354n.m2428S(c2536r.f6871a, c2536r.f6872b, c2536r2.f6871a, c2536r2.f6872b);
        float f2 = m2428S / i2;
        float f3 = c2536r.f6871a;
        float f4 = c2536r.f6872b;
        float f5 = ((c2536r2.f6871a - f3) * f2) / m2428S;
        float f6 = ((c2536r2.f6872b - f4) * f2) / m2428S;
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            float f7 = i4;
            if (this.f6883b.m2958c(C2354n.m2520u1((f7 * f5) + f3), C2354n.m2520u1((f7 * f6) + f4))) {
                i3 |= 1 << ((i2 - i4) - 1);
            }
        }
        return i3;
    }
}
