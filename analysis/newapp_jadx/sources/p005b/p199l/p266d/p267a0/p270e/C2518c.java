package p005b.p199l.p266d.p267a0.p270e;

import p005b.p199l.p266d.C2538t;
import p005b.p199l.p266d.p267a0.p268c.C2509j;
import p005b.p199l.p266d.p267a0.p268c.EnumC2505f;

/* renamed from: b.l.d.a0.e.c */
/* loaded from: classes2.dex */
public final class C2518c {

    /* renamed from: a */
    public static final int[] f6802a = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 36, -1, -1, -1, 37, 38, -1, -1, -1, -1, 39, 40, -1, 41, 42, 43, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 44, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, -1};

    /* renamed from: a */
    public static C2509j m2910a(int i2, EnumC2505f enumC2505f) {
        for (int i3 = 1; i3 <= 40; i3++) {
            C2509j m2889d = C2509j.m2889d(i3);
            if (m2912c(i2, m2889d, enumC2505f)) {
                return m2889d;
            }
        }
        throw new C2538t("Data too big");
    }

    /* renamed from: b */
    public static int m2911b(int i2) {
        int[] iArr = f6802a;
        if (i2 < iArr.length) {
            return iArr[i2];
        }
        return -1;
    }

    /* renamed from: c */
    public static boolean m2912c(int i2, C2509j c2509j, EnumC2505f enumC2505f) {
        int i3 = c2509j.f6769f;
        C2509j.b bVar = c2509j.f6768e[enumC2505f.ordinal()];
        return i3 - (bVar.m2891a() * bVar.f6772a) >= (i2 + 7) / 8;
    }
}
