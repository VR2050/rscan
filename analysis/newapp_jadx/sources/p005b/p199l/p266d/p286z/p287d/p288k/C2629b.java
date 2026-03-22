package p005b.p199l.p266d.p286z.p287d.p288k;

/* renamed from: b.l.d.z.d.k.b */
/* loaded from: classes2.dex */
public final class C2629b {

    /* renamed from: a */
    public static final C2629b f7165a = new C2629b(929, 3);

    /* renamed from: b */
    public final int[] f7166b;

    /* renamed from: c */
    public final int[] f7167c;

    /* renamed from: d */
    public final C2630c f7168d;

    /* renamed from: e */
    public final C2630c f7169e;

    public C2629b(int i2, int i3) {
        this.f7166b = new int[i2];
        this.f7167c = new int[i2];
        int i4 = 1;
        for (int i5 = 0; i5 < i2; i5++) {
            this.f7166b[i5] = i4;
            i4 = (i4 * i3) % i2;
        }
        for (int i6 = 0; i6 < i2 - 1; i6++) {
            this.f7167c[this.f7166b[i6]] = i6;
        }
        this.f7168d = new C2630c(this, new int[]{0});
        this.f7169e = new C2630c(this, new int[]{1});
    }

    /* renamed from: a */
    public int m3081a(int i2, int i3) {
        return (i2 + i3) % 929;
    }

    /* renamed from: b */
    public C2630c m3082b(int i2, int i3) {
        if (i2 < 0) {
            throw new IllegalArgumentException();
        }
        if (i3 == 0) {
            return this.f7168d;
        }
        int[] iArr = new int[i2 + 1];
        iArr[0] = i3;
        return new C2630c(this, iArr);
    }

    /* renamed from: c */
    public int m3083c(int i2) {
        if (i2 != 0) {
            return this.f7166b[(929 - this.f7167c[i2]) - 1];
        }
        throw new ArithmeticException();
    }

    /* renamed from: d */
    public int m3084d(int i2, int i3) {
        if (i2 == 0 || i3 == 0) {
            return 0;
        }
        int[] iArr = this.f7166b;
        int[] iArr2 = this.f7167c;
        return iArr[(iArr2[i2] + iArr2[i3]) % 928];
    }

    /* renamed from: e */
    public int m3085e(int i2, int i3) {
        return ((i2 + 929) - i3) % 929;
    }
}
