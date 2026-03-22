package p005b.p199l.p266d.p267a0.p270e;

import com.alibaba.fastjson.asm.Opcodes;
import p005b.p199l.p266d.C2538t;

/* renamed from: b.l.d.a0.e.d */
/* loaded from: classes2.dex */
public final class C2519d {

    /* renamed from: a */
    public static final int[][] f6803a = {new int[]{1, 1, 1, 1, 1, 1, 1}, new int[]{1, 0, 0, 0, 0, 0, 1}, new int[]{1, 0, 1, 1, 1, 0, 1}, new int[]{1, 0, 1, 1, 1, 0, 1}, new int[]{1, 0, 1, 1, 1, 0, 1}, new int[]{1, 0, 0, 0, 0, 0, 1}, new int[]{1, 1, 1, 1, 1, 1, 1}};

    /* renamed from: b */
    public static final int[][] f6804b = {new int[]{1, 1, 1, 1, 1}, new int[]{1, 0, 0, 0, 1}, new int[]{1, 0, 1, 0, 1}, new int[]{1, 0, 0, 0, 1}, new int[]{1, 1, 1, 1, 1}};

    /* renamed from: c */
    public static final int[][] f6805c = {new int[]{-1, -1, -1, -1, -1, -1, -1}, new int[]{6, 18, -1, -1, -1, -1, -1}, new int[]{6, 22, -1, -1, -1, -1, -1}, new int[]{6, 26, -1, -1, -1, -1, -1}, new int[]{6, 30, -1, -1, -1, -1, -1}, new int[]{6, 34, -1, -1, -1, -1, -1}, new int[]{6, 22, 38, -1, -1, -1, -1}, new int[]{6, 24, 42, -1, -1, -1, -1}, new int[]{6, 26, 46, -1, -1, -1, -1}, new int[]{6, 28, 50, -1, -1, -1, -1}, new int[]{6, 30, 54, -1, -1, -1, -1}, new int[]{6, 32, 58, -1, -1, -1, -1}, new int[]{6, 34, 62, -1, -1, -1, -1}, new int[]{6, 26, 46, 66, -1, -1, -1}, new int[]{6, 26, 48, 70, -1, -1, -1}, new int[]{6, 26, 50, 74, -1, -1, -1}, new int[]{6, 30, 54, 78, -1, -1, -1}, new int[]{6, 30, 56, 82, -1, -1, -1}, new int[]{6, 30, 58, 86, -1, -1, -1}, new int[]{6, 34, 62, 90, -1, -1, -1}, new int[]{6, 28, 50, 72, 94, -1, -1}, new int[]{6, 26, 50, 74, 98, -1, -1}, new int[]{6, 30, 54, 78, 102, -1, -1}, new int[]{6, 28, 54, 80, 106, -1, -1}, new int[]{6, 32, 58, 84, 110, -1, -1}, new int[]{6, 30, 58, 86, 114, -1, -1}, new int[]{6, 34, 62, 90, 118, -1, -1}, new int[]{6, 26, 50, 74, 98, 122, -1}, new int[]{6, 30, 54, 78, 102, 126, -1}, new int[]{6, 26, 52, 78, 104, 130, -1}, new int[]{6, 30, 56, 82, 108, 134, -1}, new int[]{6, 34, 60, 86, 112, 138, -1}, new int[]{6, 30, 58, 86, 114, 142, -1}, new int[]{6, 34, 62, 90, 118, 146, -1}, new int[]{6, 30, 54, 78, 102, 126, 150}, new int[]{6, 24, 50, 76, 102, 128, Opcodes.IFNE}, new int[]{6, 28, 54, 80, 106, 132, Opcodes.IFLE}, new int[]{6, 32, 58, 84, 110, 136, Opcodes.IF_ICMPGE}, new int[]{6, 26, 54, 82, 110, 138, 166}, new int[]{6, 30, 58, 86, 114, 142, 170}};

    /* renamed from: d */
    public static final int[][] f6806d = {new int[]{8, 0}, new int[]{8, 1}, new int[]{8, 2}, new int[]{8, 3}, new int[]{8, 4}, new int[]{8, 5}, new int[]{8, 7}, new int[]{8, 8}, new int[]{7, 8}, new int[]{5, 8}, new int[]{4, 8}, new int[]{3, 8}, new int[]{2, 8}, new int[]{1, 8}, new int[]{0, 8}};

    /* JADX WARN: Removed duplicated region for block: B:112:0x0237  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x023e  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x023a  */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m2913a(p005b.p199l.p266d.p274v.C2543a r20, p005b.p199l.p266d.p267a0.p268c.EnumC2505f r21, p005b.p199l.p266d.p267a0.p268c.C2509j r22, int r23, p005b.p199l.p266d.p267a0.p270e.C2517b r24) {
        /*
            Method dump skipped, instructions count: 720
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p267a0.p270e.C2519d.m2913a(b.l.d.v.a, b.l.d.a0.c.f, b.l.d.a0.c.j, int, b.l.d.a0.e.b):void");
    }

    /* renamed from: b */
    public static int m2914b(int i2, int i3) {
        if (i3 == 0) {
            throw new IllegalArgumentException("0 polynomial");
        }
        int m2918f = m2918f(i3);
        int i4 = i2 << (m2918f - 1);
        while (m2918f(i4) >= m2918f) {
            i4 ^= i3 << (m2918f(i4) - m2918f);
        }
        return i4;
    }

    /* renamed from: c */
    public static void m2915c(int i2, int i3, C2517b c2517b) {
        for (int i4 = 0; i4 < 8; i4++) {
            int i5 = i2 + i4;
            if (!m2919g(c2517b.m2907a(i5, i3))) {
                throw new C2538t();
            }
            c2517b.m2908b(i5, i3, 0);
        }
    }

    /* renamed from: d */
    public static void m2916d(int i2, int i3, C2517b c2517b) {
        for (int i4 = 0; i4 < 7; i4++) {
            int[] iArr = f6803a[i4];
            for (int i5 = 0; i5 < 7; i5++) {
                c2517b.m2908b(i2 + i5, i3 + i4, iArr[i5]);
            }
        }
    }

    /* renamed from: e */
    public static void m2917e(int i2, int i3, C2517b c2517b) {
        for (int i4 = 0; i4 < 7; i4++) {
            int i5 = i3 + i4;
            if (!m2919g(c2517b.f6799a[i5][i2])) {
                throw new C2538t();
            }
            c2517b.f6799a[i5][i2] = (byte) 0;
        }
    }

    /* renamed from: f */
    public static int m2918f(int i2) {
        return 32 - Integer.numberOfLeadingZeros(i2);
    }

    /* renamed from: g */
    public static boolean m2919g(int i2) {
        return i2 == -1;
    }
}
