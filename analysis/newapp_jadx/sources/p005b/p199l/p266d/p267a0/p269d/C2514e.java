package p005b.p199l.p266d.p267a0.p269d;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.a0.d.e */
/* loaded from: classes2.dex */
public class C2514e {

    /* renamed from: a */
    public static final b f6788a = new b(null);

    /* renamed from: b */
    public final C2544b f6789b;

    /* renamed from: d */
    public boolean f6791d;

    /* renamed from: f */
    public final InterfaceC2537s f6793f;

    /* renamed from: c */
    public final List<C2513d> f6790c = new ArrayList();

    /* renamed from: e */
    public final int[] f6792e = new int[5];

    /* renamed from: b.l.d.a0.d.e$b */
    public static final class b implements Serializable, Comparator<C2513d> {
        public b(a aVar) {
        }

        @Override // java.util.Comparator
        public int compare(C2513d c2513d, C2513d c2513d2) {
            return Float.compare(c2513d.f6786c, c2513d2.f6786c);
        }
    }

    public C2514e(C2544b c2544b, InterfaceC2537s interfaceC2537s) {
        this.f6789b = c2544b;
        this.f6793f = interfaceC2537s;
    }

    /* renamed from: a */
    public static float m2899a(int[] iArr, int i2) {
        return ((i2 - iArr[4]) - iArr[3]) - (iArr[2] / 2.0f);
    }

    /* renamed from: c */
    public static boolean m2900c(int[] iArr) {
        int i2 = 0;
        for (int i3 = 0; i3 < 5; i3++) {
            int i4 = iArr[i3];
            if (i4 == 0) {
                return false;
            }
            i2 += i4;
        }
        if (i2 < 7) {
            return false;
        }
        float f2 = i2 / 7.0f;
        float f3 = f2 / 2.0f;
        return Math.abs(f2 - ((float) iArr[0])) < f3 && Math.abs(f2 - ((float) iArr[1])) < f3 && Math.abs((f2 * 3.0f) - ((float) iArr[2])) < 3.0f * f3 && Math.abs(f2 - ((float) iArr[3])) < f3 && Math.abs(f2 - ((float) iArr[4])) < f3;
    }

    /* renamed from: h */
    public static double m2901h(C2513d c2513d, C2513d c2513d2) {
        double d2 = c2513d.f6871a - c2513d2.f6871a;
        double d3 = c2513d.f6872b - c2513d2.f6872b;
        return (d3 * d3) + (d2 * d2);
    }

    /* renamed from: b */
    public final void m2902b(int[] iArr) {
        for (int i2 = 0; i2 < iArr.length; i2++) {
            iArr[i2] = 0;
        }
    }

    /* renamed from: d */
    public final int[] m2903d() {
        m2902b(this.f6792e);
        return this.f6792e;
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x016b, code lost:
    
        if (r8 == r12) goto L122;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x016f, code lost:
    
        if (r13[3] < r1) goto L107;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0172, code lost:
    
        if (r8 >= r12) goto L253;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x0178, code lost:
    
        if (r11.m2958c(r8, r10) == false) goto L254;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x017c, code lost:
    
        if (r13[4] >= r1) goto L255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x017e, code lost:
    
        r13[4] = r13[4] + 1;
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0188, code lost:
    
        if (r13[4] < r1) goto L116;
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x01a1, code lost:
    
        if ((java.lang.Math.abs(((((r13[0] + r13[1]) + r13[2]) + r13[3]) + r13[4]) - r3) * 5) < r3) goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x01a8, code lost:
    
        if (m2900c(r13) == false) goto L122;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x01aa, code lost:
    
        r14 = m2899a(r13, r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0057, code lost:
    
        if (r12[1] <= r9) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x005b, code lost:
    
        if (r13 < 0) goto L231;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0061, code lost:
    
        if (r10.m2958c(r8, r13) == false) goto L229;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0065, code lost:
    
        if (r12[0] > r9) goto L230;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0067, code lost:
    
        r12[0] = r12[0] + 1;
        r13 = r13 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0071, code lost:
    
        if (r12[0] <= r9) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0075, code lost:
    
        r13 = r19 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0077, code lost:
    
        if (r13 >= r11) goto L232;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x007d, code lost:
    
        if (r10.m2958c(r8, r13) == false) goto L233;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x007f, code lost:
    
        r12[2] = r12[2] + 1;
        r13 = r13 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0087, code lost:
    
        if (r13 != r11) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x008a, code lost:
    
        if (r13 >= r11) goto L236;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0090, code lost:
    
        if (r10.m2958c(r8, r13) != false) goto L234;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0094, code lost:
    
        if (r12[3] >= r9) goto L235;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0096, code lost:
    
        r12[3] = r12[3] + 1;
        r13 = r13 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x009e, code lost:
    
        if (r13 == r11) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00a2, code lost:
    
        if (r12[3] < r9) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00a5, code lost:
    
        if (r13 >= r11) goto L237;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00ab, code lost:
    
        if (r10.m2958c(r8, r13) == false) goto L238;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x00af, code lost:
    
        if (r12[4] >= r9) goto L239;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00b1, code lost:
    
        r12[4] = r12[4] + 1;
        r13 = r13 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00bb, code lost:
    
        if (r12[4] < r9) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00d5, code lost:
    
        if ((java.lang.Math.abs(((((r12[0] + r12[1]) + r12[2]) + r12[3]) + r12[4]) - r3) * 5) < (r3 * 2)) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00dc, code lost:
    
        if (m2900c(r12) == false) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00de, code lost:
    
        r9 = m2899a(r12, r13);
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0125, code lost:
    
        if (r13[1] <= r1) goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0129, code lost:
    
        if (r14 < 0) goto L246;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x012f, code lost:
    
        if (r11.m2958c(r14, r10) == false) goto L247;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x0133, code lost:
    
        if (r13[0] > r1) goto L245;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x0135, code lost:
    
        r13[0] = r13[0] + 1;
        r14 = r14 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x013f, code lost:
    
        if (r13[0] <= r1) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0143, code lost:
    
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0144, code lost:
    
        if (r8 >= r12) goto L248;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x014a, code lost:
    
        if (r11.m2958c(r8, r10) == false) goto L249;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x014c, code lost:
    
        r13[2] = r13[2] + 1;
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x0154, code lost:
    
        if (r8 != r12) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x0157, code lost:
    
        if (r8 >= r12) goto L251;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x015d, code lost:
    
        if (r11.m2958c(r8, r10) != false) goto L252;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x0161, code lost:
    
        if (r13[3] >= r1) goto L250;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x0163, code lost:
    
        r13[3] = r13[3] + 1;
        r8 = r8 + 1;
     */
    /* JADX WARN: Removed duplicated region for block: B:209:0x0346 A[LOOP:19: B:197:0x02e1->B:209:0x0346, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:210:0x0322 A[SYNTHETIC] */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m2904e(int[] r18, int r19, int r20) {
        /*
            Method dump skipped, instructions count: 864
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p267a0.p269d.C2514e.m2904e(int[], int, int):boolean");
    }

    /* renamed from: f */
    public final boolean m2905f() {
        int size = this.f6790c.size();
        float f2 = 0.0f;
        int i2 = 0;
        float f3 = 0.0f;
        for (C2513d c2513d : this.f6790c) {
            if (c2513d.f6787d >= 2) {
                i2++;
                f3 += c2513d.f6786c;
            }
        }
        if (i2 < 3) {
            return false;
        }
        float f4 = f3 / size;
        Iterator<C2513d> it = this.f6790c.iterator();
        while (it.hasNext()) {
            f2 += Math.abs(it.next().f6786c - f4);
        }
        return f2 <= f3 * 0.05f;
    }

    /* renamed from: g */
    public final void m2906g(int[] iArr) {
        iArr[0] = iArr[2];
        iArr[1] = iArr[3];
        iArr[2] = iArr[4];
        iArr[3] = 1;
        iArr[4] = 0;
    }
}
