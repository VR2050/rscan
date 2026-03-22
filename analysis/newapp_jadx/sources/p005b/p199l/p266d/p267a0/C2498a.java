package p005b.p199l.p266d.p267a0;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p266d.C2521c;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.EnumC2535q;
import p005b.p199l.p266d.InterfaceC2532n;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p199l.p266d.p267a0.p268c.C2504e;
import p005b.p199l.p266d.p267a0.p268c.C2508i;
import p005b.p199l.p266d.p267a0.p268c.C2509j;
import p005b.p199l.p266d.p267a0.p269d.C2510a;
import p005b.p199l.p266d.p267a0.p269d.C2512c;
import p005b.p199l.p266d.p267a0.p269d.C2513d;
import p005b.p199l.p266d.p267a0.p269d.C2514e;
import p005b.p199l.p266d.p267a0.p269d.C2515f;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p274v.C2547e;
import p005b.p199l.p266d.p274v.C2548f;
import p005b.p199l.p266d.p274v.C2552j;

/* renamed from: b.l.d.a0.a */
/* loaded from: classes2.dex */
public class C2498a implements InterfaceC2532n {

    /* renamed from: a */
    public static final C2536r[] f6721a = new C2536r[0];

    /* renamed from: b */
    public final C2504e f6722b = new C2504e();

    @Override // p005b.p199l.p266d.InterfaceC2532n
    /* renamed from: a */
    public final C2534p mo2867a(C2521c c2521c, Map<EnumC2523e, ?> map) {
        C2513d c2513d;
        C2513d c2513d2;
        C2513d c2513d3;
        C2513d c2513d4;
        C2513d c2513d5;
        char c2;
        C2510a c2510a;
        float f2;
        float f3;
        float f4;
        C2547e m2882a;
        C2536r[] c2536rArr;
        int i2;
        int i3;
        int i4 = 1;
        if (map == null || !map.containsKey(EnumC2523e.PURE_BARCODE)) {
            C2544b m2922a = c2521c.m2922a();
            C2512c c2512c = new C2512c(m2922a);
            InterfaceC2537s interfaceC2537s = map == null ? null : (InterfaceC2537s) map.get(EnumC2523e.NEED_RESULT_POINT_CALLBACK);
            c2512c.f6785b = interfaceC2537s;
            C2514e c2514e = new C2514e(m2922a, interfaceC2537s);
            boolean z = map != null && map.containsKey(EnumC2523e.TRY_HARDER);
            int i5 = m2922a.f6894e;
            int i6 = m2922a.f6893c;
            int i7 = (i5 * 3) / 388;
            if (i7 < 3 || z) {
                i7 = 3;
            }
            int[] iArr = new int[5];
            int i8 = i7 - 1;
            boolean z2 = false;
            while (true) {
                int i9 = 4;
                if (i8 >= i5 || z2) {
                    break;
                }
                c2514e.m2902b(iArr);
                int i10 = 0;
                int i11 = 0;
                while (i11 < i6) {
                    if (c2514e.f6789b.m2958c(i11, i8)) {
                        if ((i10 & 1) == 1) {
                            i10++;
                        }
                        iArr[i10] = iArr[i10] + 1;
                    } else if ((i10 & 1) != 0) {
                        iArr[i10] = iArr[i10] + 1;
                    } else if (i10 == i9) {
                        if (!C2514e.m2900c(iArr)) {
                            c2514e.m2906g(iArr);
                        } else if (c2514e.m2904e(iArr, i8, i11)) {
                            if (c2514e.f6791d) {
                                z2 = c2514e.m2905f();
                            } else {
                                if (c2514e.f6790c.size() > 1) {
                                    C2513d c2513d6 = null;
                                    for (C2513d c2513d7 : c2514e.f6790c) {
                                        if (c2513d7.f6787d >= 2) {
                                            if (c2513d6 != null) {
                                                c2514e.f6791d = true;
                                                int abs = (int) (Math.abs(c2513d6.f6871a - c2513d7.f6871a) - Math.abs(c2513d6.f6872b - c2513d7.f6872b));
                                                i2 = 2;
                                                i3 = abs / 2;
                                                break;
                                            }
                                            c2513d6 = c2513d7;
                                        }
                                    }
                                }
                                i2 = 2;
                                i3 = 0;
                                if (i3 > iArr[i2]) {
                                    i8 += (i3 - iArr[i2]) - i2;
                                    i11 = i6 - 1;
                                }
                            }
                            c2514e.m2902b(iArr);
                            i7 = 2;
                            i10 = 0;
                        } else {
                            c2514e.m2906g(iArr);
                        }
                        i10 = 3;
                    } else {
                        i10++;
                        iArr[i10] = iArr[i10] + 1;
                    }
                    i11++;
                    i9 = 4;
                }
                if (C2514e.m2900c(iArr) && c2514e.m2904e(iArr, i8, i6)) {
                    i7 = iArr[0];
                    if (c2514e.f6791d) {
                        z2 = c2514e.m2905f();
                    }
                }
                i8 += i7;
            }
            if (c2514e.f6790c.size() < 3) {
                throw C2529k.f6843f;
            }
            c2514e.f6790c.sort(C2514e.f6788a);
            double[] dArr = new double[3];
            C2513d[] c2513dArr = new C2513d[3];
            int i12 = 0;
            double d2 = Double.MAX_VALUE;
            while (i12 < c2514e.f6790c.size() - 2) {
                C2513d c2513d8 = c2514e.f6790c.get(i12);
                float f5 = c2513d8.f6786c;
                i12++;
                int i13 = i12;
                while (i13 < c2514e.f6790c.size() - i4) {
                    C2513d c2513d9 = c2514e.f6790c.get(i13);
                    double m2901h = C2514e.m2901h(c2513d8, c2513d9);
                    i13++;
                    int i14 = i12;
                    int i15 = i4;
                    int i16 = i13;
                    while (i16 < c2514e.f6790c.size()) {
                        C2513d c2513d10 = c2514e.f6790c.get(i16);
                        C2514e c2514e2 = c2514e;
                        if (c2513d10.f6786c <= 1.4f * f5) {
                            dArr[0] = m2901h;
                            dArr[1] = C2514e.m2901h(c2513d9, c2513d10);
                            dArr[2] = C2514e.m2901h(c2513d8, c2513d10);
                            Arrays.sort(dArr);
                            double abs2 = Math.abs(dArr[2] - (dArr[0] * 2.0d)) + Math.abs(dArr[2] - (dArr[1] * 2.0d));
                            if (abs2 < d2) {
                                c2513dArr[0] = c2513d8;
                                c2513dArr[1] = c2513d9;
                                c2513dArr[2] = c2513d10;
                                d2 = abs2;
                            }
                        }
                        i16++;
                        i15 = 1;
                        c2514e = c2514e2;
                    }
                    i12 = i14;
                    i4 = i15;
                }
            }
            if (d2 == Double.MAX_VALUE) {
                throw C2529k.f6843f;
            }
            float m2934a = C2536r.m2934a(c2513dArr[0], c2513dArr[1]);
            float m2934a2 = C2536r.m2934a(c2513dArr[1], c2513dArr[2]);
            float m2934a3 = C2536r.m2934a(c2513dArr[0], c2513dArr[2]);
            if (m2934a2 < m2934a || m2934a2 < m2934a3) {
                if (m2934a3 < m2934a2 || m2934a3 < m2934a) {
                    c2513d = c2513dArr[2];
                    c2513d2 = c2513dArr[0];
                    c2513d3 = c2513dArr[1];
                } else {
                    c2513d = c2513dArr[1];
                    c2513d2 = c2513dArr[0];
                    c2513d3 = c2513dArr[2];
                }
                C2513d c2513d11 = c2513d;
                c2513d4 = c2513d2;
                c2513d5 = c2513d11;
            } else {
                c2513d5 = c2513dArr[0];
                c2513d4 = c2513dArr[1];
                c2513d3 = c2513dArr[2];
            }
            float f6 = c2513d5.f6871a;
            float f7 = c2513d5.f6872b;
            if (((c2513d4.f6872b - f7) * (c2513d3.f6871a - f6)) - ((c2513d4.f6871a - f6) * (c2513d3.f6872b - f7)) < 0.0f) {
                c2 = 0;
                C2513d c2513d12 = c2513d3;
                c2513d3 = c2513d4;
                c2513d4 = c2513d12;
            } else {
                c2 = 0;
            }
            c2513dArr[c2] = c2513d4;
            c2513dArr[1] = c2513d5;
            c2513dArr[2] = c2513d3;
            C2515f c2515f = new C2515f(c2513dArr);
            C2513d c2513d13 = c2515f.f6795b;
            C2513d c2513d14 = c2515f.f6796c;
            C2513d c2513d15 = c2515f.f6794a;
            float m2895a = (c2512c.m2895a(c2513d13, c2513d15) + c2512c.m2895a(c2513d13, c2513d14)) / 2.0f;
            if (m2895a < 1.0f) {
                throw C2529k.f6843f;
            }
            int m2520u1 = ((C2354n.m2520u1(C2354n.m2428S(c2513d13.f6871a, c2513d13.f6872b, c2513d15.f6871a, c2513d15.f6872b) / m2895a) + C2354n.m2520u1(C2354n.m2428S(c2513d13.f6871a, c2513d13.f6872b, c2513d14.f6871a, c2513d14.f6872b) / m2895a)) / 2) + 7;
            int i17 = m2520u1 & 3;
            if (i17 == 0) {
                m2520u1++;
            } else if (i17 == 2) {
                m2520u1--;
            } else if (i17 == 3) {
                throw C2529k.f6843f;
            }
            int[] iArr2 = C2509j.f6764a;
            if (m2520u1 % 4 != 1) {
                throw C2525g.m2925a();
            }
            try {
                C2509j m2889d = C2509j.m2889d((m2520u1 - 17) / 4);
                int m2890c = m2889d.m2890c() - 7;
                if (m2889d.f6767d.length > 0) {
                    float f8 = c2513d14.f6871a;
                    float f9 = c2513d13.f6871a;
                    float f10 = (f8 - f9) + c2513d15.f6871a;
                    float f11 = c2513d14.f6872b;
                    float f12 = c2513d13.f6872b;
                    float f13 = (f11 - f12) + c2513d15.f6872b;
                    float f14 = 1.0f - (3.0f / m2890c);
                    int m627m = (int) C1499a.m627m(f10, f9, f14, f9);
                    int m627m2 = (int) C1499a.m627m(f13, f12, f14, f12);
                    for (int i18 = 4; i18 <= 16; i18 <<= 1) {
                        try {
                            c2510a = c2512c.m2896b(m2895a, m627m, m627m2, i18);
                            break;
                        } catch (C2529k unused) {
                        }
                    }
                }
                c2510a = null;
                float f15 = m2520u1 - 3.5f;
                if (c2510a != null) {
                    f2 = c2510a.f6871a;
                    f3 = c2510a.f6872b;
                    f4 = f15 - 3.0f;
                } else {
                    f2 = (c2513d14.f6871a - c2513d13.f6871a) + c2513d15.f6871a;
                    f3 = (c2513d14.f6872b - c2513d13.f6872b) + c2513d15.f6872b;
                    f4 = f15;
                }
                C2544b m2967a = C2548f.f6940a.m2967a(c2512c.f6784a, m2520u1, m2520u1, C2552j.m2970a(3.5f, 3.5f, f15, 3.5f, f4, f4, 3.5f, f15, c2513d13.f6871a, c2513d13.f6872b, c2513d14.f6871a, c2513d14.f6872b, f2, f3, c2513d15.f6871a, c2513d15.f6872b));
                C2536r[] c2536rArr2 = c2510a == null ? new C2536r[]{c2513d15, c2513d13, c2513d14} : new C2536r[]{c2513d15, c2513d13, c2513d14, c2510a};
                m2882a = this.f6722b.m2882a(m2967a, map);
                c2536rArr = c2536rArr2;
            } catch (IllegalArgumentException unused2) {
                throw C2525g.m2925a();
            }
        } else {
            C2544b m2922a2 = c2521c.m2922a();
            int[] m2961g = m2922a2.m2961g();
            int[] m2959d = m2922a2.m2959d();
            if (m2961g == null || m2959d == null) {
                throw C2529k.f6843f;
            }
            int i19 = m2922a2.f6894e;
            int i20 = m2922a2.f6893c;
            int i21 = m2961g[0];
            int i22 = m2961g[1];
            boolean z3 = true;
            int i23 = 0;
            while (i21 < i20 && i22 < i19) {
                if (z3 != m2922a2.m2958c(i21, i22)) {
                    i23++;
                    if (i23 == 5) {
                        break;
                    }
                    z3 = !z3;
                }
                i21++;
                i22++;
            }
            if (i21 == i20 || i22 == i19) {
                throw C2529k.f6843f;
            }
            float f16 = (i21 - m2961g[0]) / 7.0f;
            int i24 = m2961g[1];
            int i25 = m2959d[1];
            int i26 = m2961g[0];
            int i27 = m2959d[0];
            if (i26 >= i27 || i24 >= i25) {
                throw C2529k.f6843f;
            }
            int i28 = i25 - i24;
            if (i28 != i27 - i26 && (i27 = i26 + i28) >= m2922a2.f6893c) {
                throw C2529k.f6843f;
            }
            int round = Math.round(((i27 - i26) + 1) / f16);
            int round2 = Math.round((i28 + 1) / f16);
            if (round <= 0 || round2 <= 0) {
                throw C2529k.f6843f;
            }
            if (round2 != round) {
                throw C2529k.f6843f;
            }
            int i29 = (int) (f16 / 2.0f);
            int i30 = i24 + i29;
            int i31 = i26 + i29;
            int i32 = (((int) ((round - 1) * f16)) + i31) - i27;
            if (i32 > 0) {
                if (i32 > i29) {
                    throw C2529k.f6843f;
                }
                i31 -= i32;
            }
            int i33 = (((int) ((round2 - 1) * f16)) + i30) - i25;
            if (i33 > 0) {
                if (i33 > i29) {
                    throw C2529k.f6843f;
                }
                i30 -= i33;
            }
            C2544b c2544b = new C2544b(round, round2);
            for (int i34 = 0; i34 < round2; i34++) {
                int i35 = ((int) (i34 * f16)) + i30;
                for (int i36 = 0; i36 < round; i36++) {
                    if (m2922a2.m2958c(((int) (i36 * f16)) + i31, i35)) {
                        c2544b.m2962h(i36, i34);
                    }
                }
            }
            m2882a = this.f6722b.m2882a(c2544b, map);
            c2536rArr = f6721a;
        }
        Object obj = m2882a.f6937f;
        if ((obj instanceof C2508i) && ((C2508i) obj).f6763a && c2536rArr.length >= 3) {
            C2536r c2536r = c2536rArr[0];
            c2536rArr[0] = c2536rArr[2];
            c2536rArr[2] = c2536r;
        }
        C2534p c2534p = new C2534p(m2882a.f6934c, m2882a.f6932a, c2536rArr, EnumC2497a.QR_CODE);
        List<byte[]> list = m2882a.f6935d;
        if (list != null) {
            c2534p.m2933b(EnumC2535q.BYTE_SEGMENTS, list);
        }
        String str = m2882a.f6936e;
        if (str != null) {
            c2534p.m2933b(EnumC2535q.ERROR_CORRECTION_LEVEL, str);
        }
        if (m2882a.f6938g >= 0 && m2882a.f6939h >= 0) {
            c2534p.m2933b(EnumC2535q.STRUCTURED_APPEND_SEQUENCE, Integer.valueOf(m2882a.f6939h));
            c2534p.m2933b(EnumC2535q.STRUCTURED_APPEND_PARITY, Integer.valueOf(m2882a.f6938g));
        }
        return c2534p;
    }

    @Override // p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
    }
}
