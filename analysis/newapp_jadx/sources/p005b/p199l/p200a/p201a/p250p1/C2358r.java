package p005b.p199l.p200a.p201a.p250p1;

import java.util.Arrays;

/* renamed from: b.l.a.a.p1.r */
/* loaded from: classes.dex */
public final class C2358r {

    /* renamed from: a */
    public static final byte[] f6109a = {0, 0, 0, 1};

    /* renamed from: b */
    public static final float[] f6110b = {1.0f, 1.0f, 1.0909091f, 0.90909094f, 1.4545455f, 1.2121212f, 2.1818182f, 1.8181819f, 2.909091f, 2.4242425f, 1.6363636f, 1.3636364f, 1.939394f, 1.6161616f, 1.3333334f, 1.5f, 2.0f};

    /* renamed from: c */
    public static final Object f6111c = new Object();

    /* renamed from: d */
    public static int[] f6112d = new int[10];

    /* renamed from: b.l.a.a.p1.r$a */
    public static final class a {

        /* renamed from: a */
        public final int f6113a;

        /* renamed from: b */
        public final int f6114b;

        /* renamed from: c */
        public final boolean f6115c;

        public a(int i2, int i3, boolean z) {
            this.f6113a = i2;
            this.f6114b = i3;
            this.f6115c = z;
        }
    }

    /* renamed from: b.l.a.a.p1.r$b */
    public static final class b {

        /* renamed from: a */
        public final int f6116a;

        /* renamed from: b */
        public final int f6117b;

        /* renamed from: c */
        public final int f6118c;

        /* renamed from: d */
        public final int f6119d;

        /* renamed from: e */
        public final int f6120e;

        /* renamed from: f */
        public final int f6121f;

        /* renamed from: g */
        public final float f6122g;

        /* renamed from: h */
        public final boolean f6123h;

        /* renamed from: i */
        public final boolean f6124i;

        /* renamed from: j */
        public final int f6125j;

        /* renamed from: k */
        public final int f6126k;

        /* renamed from: l */
        public final int f6127l;

        /* renamed from: m */
        public final boolean f6128m;

        public b(int i2, int i3, int i4, int i5, int i6, int i7, float f2, boolean z, boolean z2, int i8, int i9, int i10, boolean z3) {
            this.f6116a = i2;
            this.f6117b = i3;
            this.f6118c = i4;
            this.f6119d = i5;
            this.f6120e = i6;
            this.f6121f = i7;
            this.f6122g = f2;
            this.f6123h = z;
            this.f6124i = z2;
            this.f6125j = i8;
            this.f6126k = i9;
            this.f6127l = i10;
            this.f6128m = z3;
        }
    }

    /* renamed from: a */
    public static void m2548a(boolean[] zArr) {
        zArr[0] = false;
        zArr[1] = false;
        zArr[2] = false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:57:0x00a3, code lost:
    
        r8 = true;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int m2549b(byte[] r7, int r8, int r9, boolean[] r10) {
        /*
            Method dump skipped, instructions count: 200
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2358r.m2549b(byte[], int, int, boolean[]):int");
    }

    /* renamed from: c */
    public static a m2550c(byte[] bArr, int i2, int i3) {
        C2361u c2361u = new C2361u(bArr, i2, i3);
        c2361u.m2604j(8);
        int m2600f = c2361u.m2600f();
        int m2600f2 = c2361u.m2600f();
        c2361u.m2603i();
        return new a(m2600f, m2600f2, c2361u.m2598d());
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0162  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p199l.p200a.p201a.p250p1.C2358r.b m2551d(byte[] r21, int r22, int r23) {
        /*
            Method dump skipped, instructions count: 375
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2358r.m2551d(byte[], int, int):b.l.a.a.p1.r$b");
    }

    /* renamed from: e */
    public static int m2552e(byte[] bArr, int i2) {
        int i3;
        synchronized (f6111c) {
            int i4 = 0;
            int i5 = 0;
            while (i4 < i2) {
                while (true) {
                    if (i4 >= i2 - 2) {
                        i4 = i2;
                        break;
                    }
                    if (bArr[i4] == 0 && bArr[i4 + 1] == 0 && bArr[i4 + 2] == 3) {
                        break;
                    }
                    i4++;
                }
                if (i4 < i2) {
                    int[] iArr = f6112d;
                    if (iArr.length <= i5) {
                        f6112d = Arrays.copyOf(iArr, iArr.length * 2);
                    }
                    f6112d[i5] = i4;
                    i4 += 3;
                    i5++;
                }
            }
            i3 = i2 - i5;
            int i6 = 0;
            int i7 = 0;
            for (int i8 = 0; i8 < i5; i8++) {
                int i9 = f6112d[i8] - i7;
                System.arraycopy(bArr, i7, bArr, i6, i9);
                int i10 = i6 + i9;
                int i11 = i10 + 1;
                bArr[i10] = 0;
                i6 = i11 + 1;
                bArr[i11] = 0;
                i7 += i9 + 3;
            }
            System.arraycopy(bArr, i7, bArr, i6, i3 - i6);
        }
        return i3;
    }
}
