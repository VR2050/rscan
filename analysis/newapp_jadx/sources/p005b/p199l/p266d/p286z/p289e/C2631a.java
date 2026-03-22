package p005b.p199l.p266d.p286z.p289e;

import java.util.Arrays;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.z.e.a */
/* loaded from: classes2.dex */
public final class C2631a {

    /* renamed from: a */
    public static final int[] f7172a = {0, 4, 1, 5};

    /* renamed from: b */
    public static final int[] f7173b = {6, 2, 7, 3};

    /* renamed from: c */
    public static final int[] f7174c = {8, 1, 1, 1, 1, 1, 1, 3};

    /* renamed from: d */
    public static final int[] f7175d = {7, 1, 1, 3, 1, 1, 1, 2, 1};

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0068, code lost:
    
        if (r12 == false) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x006a, code lost:
    
        r1 = r7.iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0072, code lost:
    
        if (r1.hasNext() == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0074, code lost:
    
        r2 = (p005b.p199l.p266d.C2536r[]) r1.next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x007c, code lost:
    
        if (r2[1] == null) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x007e, code lost:
    
        r10 = (int) java.lang.Math.max(r10, r2[1].f6872b);
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x008a, code lost:
    
        if (r2[3] == null) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x008c, code lost:
    
        r10 = java.lang.Math.max(r10, (int) r2[3].f6872b);
     */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.List<p005b.p199l.p266d.C2536r[]> m3095a(boolean r17, p005b.p199l.p266d.p274v.C2544b r18) {
        /*
            Method dump skipped, instructions count: 189
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p286z.p289e.C2631a.m3095a(boolean, b.l.d.v.b):java.util.List");
    }

    /* renamed from: b */
    public static int[] m3096b(C2544b c2544b, int i2, int i3, int i4, boolean z, int[] iArr, int[] iArr2) {
        Arrays.fill(iArr2, 0, iArr2.length, 0);
        int i5 = 0;
        while (c2544b.m2958c(i2, i3) && i2 > 0) {
            int i6 = i5 + 1;
            if (i5 >= 3) {
                break;
            }
            i2--;
            i5 = i6;
        }
        int length = iArr.length;
        boolean z2 = z;
        int i7 = 0;
        int i8 = i2;
        while (i2 < i4) {
            if (c2544b.m2958c(i2, i3) != z2) {
                iArr2[i7] = iArr2[i7] + 1;
            } else {
                if (i7 != length - 1) {
                    i7++;
                } else {
                    if (m3098d(iArr2, iArr, 0.8f) < 0.42f) {
                        return new int[]{i8, i2};
                    }
                    i8 += iArr2[0] + iArr2[1];
                    int i9 = i7 - 1;
                    System.arraycopy(iArr2, 2, iArr2, 0, i9);
                    iArr2[i9] = 0;
                    iArr2[i7] = 0;
                    i7 = i9;
                }
                iArr2[i7] = 1;
                z2 = !z2;
            }
            i2++;
        }
        if (i7 != length - 1 || m3098d(iArr2, iArr, 0.8f) >= 0.42f) {
            return null;
        }
        return new int[]{i8, i2 - 1};
    }

    /* renamed from: c */
    public static C2536r[] m3097c(C2544b c2544b, int i2, int i3, int i4, int i5, int[] iArr) {
        boolean z;
        int i6;
        int i7;
        int i8;
        C2536r[] c2536rArr = new C2536r[4];
        int[] iArr2 = new int[iArr.length];
        int i9 = i4;
        while (true) {
            if (i9 >= i2) {
                z = false;
                break;
            }
            int[] m3096b = m3096b(c2544b, i5, i9, i3, false, iArr, iArr2);
            if (m3096b != null) {
                int i10 = i9;
                int[] iArr3 = m3096b;
                int i11 = i10;
                while (true) {
                    if (i11 <= 0) {
                        i8 = i11;
                        break;
                    }
                    int i12 = i11 - 1;
                    int[] m3096b2 = m3096b(c2544b, i5, i12, i3, false, iArr, iArr2);
                    if (m3096b2 == null) {
                        i8 = i12 + 1;
                        break;
                    }
                    iArr3 = m3096b2;
                    i11 = i12;
                }
                float f2 = i8;
                c2536rArr[0] = new C2536r(iArr3[0], f2);
                c2536rArr[1] = new C2536r(iArr3[1], f2);
                i9 = i8;
                z = true;
            } else {
                i9 += 5;
            }
        }
        int i13 = i9 + 1;
        if (z) {
            int[] iArr4 = {(int) c2536rArr[0].f6871a, (int) c2536rArr[1].f6871a};
            int i14 = i13;
            int i15 = 0;
            while (true) {
                if (i14 >= i2) {
                    i6 = i15;
                    i7 = i14;
                    break;
                }
                i6 = i15;
                i7 = i14;
                int[] m3096b3 = m3096b(c2544b, iArr4[0], i14, i3, false, iArr, iArr2);
                if (m3096b3 != null && Math.abs(iArr4[0] - m3096b3[0]) < 5 && Math.abs(iArr4[1] - m3096b3[1]) < 5) {
                    iArr4 = m3096b3;
                    i15 = 0;
                } else {
                    if (i6 > 25) {
                        break;
                    }
                    i15 = i6 + 1;
                }
                i14 = i7 + 1;
            }
            i13 = i7 - (i6 + 1);
            float f3 = i13;
            c2536rArr[2] = new C2536r(iArr4[0], f3);
            c2536rArr[3] = new C2536r(iArr4[1], f3);
        }
        if (i13 - i9 < 10) {
            Arrays.fill(c2536rArr, (Object) null);
        }
        return c2536rArr;
    }

    /* renamed from: d */
    public static float m3098d(int[] iArr, int[] iArr2, float f2) {
        int length = iArr.length;
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < length; i4++) {
            i2 += iArr[i4];
            i3 += iArr2[i4];
        }
        if (i2 < i3) {
            return Float.POSITIVE_INFINITY;
        }
        float f3 = i2;
        float f4 = f3 / i3;
        float f5 = f2 * f4;
        float f6 = 0.0f;
        for (int i5 = 0; i5 < length; i5++) {
            float f7 = iArr2[i5] * f4;
            float f8 = iArr[i5];
            float f9 = f8 > f7 ? f8 - f7 : f7 - f8;
            if (f9 > f5) {
                return Float.POSITIVE_INFINITY;
            }
            f6 += f9;
        }
        return f6 / f3;
    }
}
