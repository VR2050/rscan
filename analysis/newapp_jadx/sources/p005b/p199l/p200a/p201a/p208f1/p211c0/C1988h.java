package p005b.p199l.p200a.p201a.p208f1.p211c0;

import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.f1.c0.h */
/* loaded from: classes.dex */
public final class C1988h {

    /* renamed from: a */
    public static final int[] f3677a = {1769172845, 1769172786, 1769172787, 1769172788, 1769172789, 1769172790, 1635148593, 1752589105, 1751479857, 1635135537, 1836069937, 1836069938, 862401121, 862401122, 862417462, 862417718, 862414134, 862414646, 1295275552, 1295270176, 1714714144, 1801741417, 1295275600, 1903435808, 1297305174, 1684175153};

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r8v20 */
    /* renamed from: a */
    public static boolean m1539a(C2003e c2003e, boolean z) {
        boolean z2;
        int i2;
        int i3;
        long j2 = c2003e.f3788c;
        long j3 = IjkMediaMeta.AV_CH_TOP_FRONT_LEFT;
        long j4 = -1;
        if (j2 != -1 && j2 <= IjkMediaMeta.AV_CH_TOP_FRONT_LEFT) {
            j3 = j2;
        }
        int i4 = (int) j3;
        C2360t c2360t = new C2360t(64);
        ?? r8 = 0;
        int i5 = 0;
        boolean z3 = false;
        while (i5 < i4) {
            c2360t.m2593y(8);
            c2003e.m1565e(c2360t.f6133a, r8, 8, r8);
            long m2586r = c2360t.m2586r();
            int m2573e = c2360t.m2573e();
            if (m2586r == 1) {
                c2003e.m1565e(c2360t.f6133a, 8, 8, r8);
                c2360t.m2566B(16);
                m2586r = c2360t.m2579k();
                i2 = i5;
                i3 = 16;
            } else {
                i2 = i5;
                if (m2586r == 0) {
                    long j5 = c2003e.f3788c;
                    if (j5 != j4) {
                        m2586r = 8 + (j5 - c2003e.m1564d());
                    }
                }
                i3 = 8;
            }
            long j6 = i3;
            if (m2586r < j6) {
                return false;
            }
            i5 = i2 + i3;
            if (m2573e == 1836019574) {
                i4 += (int) m2586r;
                if (j2 != -1 && i4 > j2) {
                    i4 = (int) j2;
                }
            } else {
                if (m2573e == 1836019558 || m2573e == 1836475768) {
                    z2 = true;
                    break;
                }
                if ((i5 + m2586r) - j6 >= i4) {
                    break;
                }
                int i6 = (int) (m2586r - j6);
                i5 += i6;
                if (m2573e == 1718909296) {
                    if (i6 < 8) {
                        return false;
                    }
                    c2360t.m2593y(i6);
                    c2003e.m1565e(c2360t.f6133a, 0, i6, false);
                    int i7 = i6 / 4;
                    int i8 = 0;
                    while (true) {
                        if (i8 >= i7) {
                            break;
                        }
                        boolean z4 = true;
                        if (i8 == 1) {
                            c2360t.m2568D(4);
                        } else {
                            int m2573e2 = c2360t.m2573e();
                            if ((m2573e2 >>> 8) != 3368816) {
                                int[] iArr = f3677a;
                                int length = iArr.length;
                                int i9 = 0;
                                while (true) {
                                    if (i9 >= length) {
                                        z4 = false;
                                        break;
                                    }
                                    if (iArr[i9] == m2573e2) {
                                        z4 = true;
                                        break;
                                    }
                                    i9++;
                                }
                            }
                            if (z4) {
                                z3 = true;
                                break;
                            }
                        }
                        i8++;
                    }
                    if (!z3) {
                        return false;
                    }
                } else if (i6 != 0) {
                    c2003e.m1561a(i6, false);
                }
            }
            j4 = -1;
            r8 = 0;
        }
        z2 = false;
        return z3 && z == z2;
    }
}
