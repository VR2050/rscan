package p005b.p199l.p266d.p286z.p287d.p288k;

/* renamed from: b.l.d.z.d.k.c */
/* loaded from: classes2.dex */
public final class C2630c {

    /* renamed from: a */
    public final C2629b f7170a;

    /* renamed from: b */
    public final int[] f7171b;

    public C2630c(C2629b c2629b, int[] iArr) {
        if (iArr.length == 0) {
            throw new IllegalArgumentException();
        }
        this.f7170a = c2629b;
        int length = iArr.length;
        if (length <= 1 || iArr[0] != 0) {
            this.f7171b = iArr;
            return;
        }
        int i2 = 1;
        while (i2 < length && iArr[i2] == 0) {
            i2++;
        }
        if (i2 == length) {
            this.f7171b = new int[]{0};
            return;
        }
        int[] iArr2 = new int[length - i2];
        this.f7171b = iArr2;
        System.arraycopy(iArr, i2, iArr2, 0, iArr2.length);
    }

    /* renamed from: a */
    public C2630c m3086a(C2630c c2630c) {
        if (!this.f7170a.equals(c2630c.f7170a)) {
            throw new IllegalArgumentException("ModulusPolys do not have same ModulusGF field");
        }
        if (m3090e()) {
            return c2630c;
        }
        if (c2630c.m3090e()) {
            return this;
        }
        int[] iArr = this.f7171b;
        int[] iArr2 = c2630c.f7171b;
        if (iArr.length <= iArr2.length) {
            iArr = iArr2;
            iArr2 = iArr;
        }
        int[] iArr3 = new int[iArr.length];
        int length = iArr.length - iArr2.length;
        System.arraycopy(iArr, 0, iArr3, 0, length);
        for (int i2 = length; i2 < iArr.length; i2++) {
            iArr3[i2] = this.f7170a.m3081a(iArr2[i2 - length], iArr[i2]);
        }
        return new C2630c(this.f7170a, iArr3);
    }

    /* renamed from: b */
    public int m3087b(int i2) {
        if (i2 == 0) {
            return m3088c(0);
        }
        if (i2 == 1) {
            int i3 = 0;
            for (int i4 : this.f7171b) {
                i3 = this.f7170a.m3081a(i3, i4);
            }
            return i3;
        }
        int[] iArr = this.f7171b;
        int i5 = iArr[0];
        int length = iArr.length;
        for (int i6 = 1; i6 < length; i6++) {
            C2629b c2629b = this.f7170a;
            i5 = c2629b.m3081a(c2629b.m3084d(i2, i5), this.f7171b[i6]);
        }
        return i5;
    }

    /* renamed from: c */
    public int m3088c(int i2) {
        return this.f7171b[(r0.length - 1) - i2];
    }

    /* renamed from: d */
    public int m3089d() {
        return this.f7171b.length - 1;
    }

    /* renamed from: e */
    public boolean m3090e() {
        return this.f7171b[0] == 0;
    }

    /* renamed from: f */
    public C2630c m3091f(int i2) {
        if (i2 == 0) {
            return this.f7170a.f7168d;
        }
        if (i2 == 1) {
            return this;
        }
        int length = this.f7171b.length;
        int[] iArr = new int[length];
        for (int i3 = 0; i3 < length; i3++) {
            iArr[i3] = this.f7170a.m3084d(this.f7171b[i3], i2);
        }
        return new C2630c(this.f7170a, iArr);
    }

    /* renamed from: g */
    public C2630c m3092g(C2630c c2630c) {
        if (!this.f7170a.equals(c2630c.f7170a)) {
            throw new IllegalArgumentException("ModulusPolys do not have same ModulusGF field");
        }
        if (m3090e() || c2630c.m3090e()) {
            return this.f7170a.f7168d;
        }
        int[] iArr = this.f7171b;
        int length = iArr.length;
        int[] iArr2 = c2630c.f7171b;
        int length2 = iArr2.length;
        int[] iArr3 = new int[(length + length2) - 1];
        for (int i2 = 0; i2 < length; i2++) {
            int i3 = iArr[i2];
            for (int i4 = 0; i4 < length2; i4++) {
                int i5 = i2 + i4;
                C2629b c2629b = this.f7170a;
                iArr3[i5] = c2629b.m3081a(iArr3[i5], c2629b.m3084d(i3, iArr2[i4]));
            }
        }
        return new C2630c(this.f7170a, iArr3);
    }

    /* renamed from: h */
    public C2630c m3093h() {
        int length = this.f7171b.length;
        int[] iArr = new int[length];
        for (int i2 = 0; i2 < length; i2++) {
            iArr[i2] = this.f7170a.m3085e(0, this.f7171b[i2]);
        }
        return new C2630c(this.f7170a, iArr);
    }

    /* renamed from: i */
    public C2630c m3094i(C2630c c2630c) {
        if (this.f7170a.equals(c2630c.f7170a)) {
            return c2630c.m3090e() ? this : m3086a(c2630c.m3093h());
        }
        throw new IllegalArgumentException("ModulusPolys do not have same ModulusGF field");
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(m3089d() * 8);
        for (int m3089d = m3089d(); m3089d >= 0; m3089d--) {
            int m3088c = m3088c(m3089d);
            if (m3088c != 0) {
                if (m3088c < 0) {
                    sb.append(" - ");
                    m3088c = -m3088c;
                } else if (sb.length() > 0) {
                    sb.append(" + ");
                }
                if (m3089d == 0 || m3088c != 1) {
                    sb.append(m3088c);
                }
                if (m3089d != 0) {
                    if (m3089d == 1) {
                        sb.append('x');
                    } else {
                        sb.append("x^");
                        sb.append(m3089d);
                    }
                }
            }
        }
        return sb.toString();
    }
}
