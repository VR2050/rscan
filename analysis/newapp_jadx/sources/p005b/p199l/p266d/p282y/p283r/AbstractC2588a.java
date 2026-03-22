package p005b.p199l.p266d.p282y.p283r;

import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.p282y.AbstractC2581k;

/* renamed from: b.l.d.y.r.a */
/* loaded from: classes2.dex */
public abstract class AbstractC2588a extends AbstractC2581k {

    /* renamed from: b */
    public final int[] f7067b;

    /* renamed from: e */
    public final int[] f7070e;

    /* renamed from: f */
    public final int[] f7071f;

    /* renamed from: a */
    public final int[] f7066a = new int[4];

    /* renamed from: c */
    public final float[] f7068c = new float[4];

    /* renamed from: d */
    public final float[] f7069d = new float[4];

    public AbstractC2588a() {
        int[] iArr = new int[8];
        this.f7067b = iArr;
        this.f7070e = new int[iArr.length / 2];
        this.f7071f = new int[iArr.length / 2];
    }

    /* renamed from: g */
    public static void m3026g(int[] iArr, float[] fArr) {
        int i2 = 0;
        float f2 = fArr[0];
        for (int i3 = 1; i3 < iArr.length; i3++) {
            if (fArr[i3] < f2) {
                f2 = fArr[i3];
                i2 = i3;
            }
        }
        iArr[i2] = iArr[i2] - 1;
    }

    /* renamed from: h */
    public static void m3027h(int[] iArr, float[] fArr) {
        int i2 = 0;
        float f2 = fArr[0];
        for (int i3 = 1; i3 < iArr.length; i3++) {
            if (fArr[i3] > f2) {
                f2 = fArr[i3];
                i2 = i3;
            }
        }
        iArr[i2] = iArr[i2] + 1;
    }

    /* renamed from: i */
    public static boolean m3028i(int[] iArr) {
        float f2 = (iArr[0] + iArr[1]) / ((iArr[2] + r1) + iArr[3]);
        if (f2 >= 0.7916667f && f2 <= 0.89285713f) {
            int i2 = Integer.MAX_VALUE;
            int i3 = Integer.MIN_VALUE;
            for (int i4 : iArr) {
                if (i4 > i3) {
                    i3 = i4;
                }
                if (i4 < i2) {
                    i2 = i4;
                }
            }
            if (i3 < i2 * 10) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: j */
    public static int m3029j(int[] iArr, int[][] iArr2) {
        for (int i2 = 0; i2 < iArr2.length; i2++) {
            if (AbstractC2581k.m3013d(iArr, iArr2[i2], 0.45f) < 0.2f) {
                return i2;
            }
        }
        throw C2529k.f6843f;
    }
}
