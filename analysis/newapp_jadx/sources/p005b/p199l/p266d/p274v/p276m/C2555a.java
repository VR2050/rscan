package p005b.p199l.p266d.p274v.p276m;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.d.v.m.a */
/* loaded from: classes2.dex */
public final class C2555a {

    /* renamed from: a */
    public static final C2555a f6965a = new C2555a(4201, 4096, 1);

    /* renamed from: b */
    public static final C2555a f6966b = new C2555a(1033, 1024, 1);

    /* renamed from: c */
    public static final C2555a f6967c;

    /* renamed from: d */
    public static final C2555a f6968d;

    /* renamed from: e */
    public static final C2555a f6969e;

    /* renamed from: f */
    public static final C2555a f6970f;

    /* renamed from: g */
    public static final C2555a f6971g;

    /* renamed from: h */
    public static final C2555a f6972h;

    /* renamed from: i */
    public final int[] f6973i;

    /* renamed from: j */
    public final int[] f6974j;

    /* renamed from: k */
    public final C2556b f6975k;

    /* renamed from: l */
    public final C2556b f6976l;

    /* renamed from: m */
    public final int f6977m;

    /* renamed from: n */
    public final int f6978n;

    /* renamed from: o */
    public final int f6979o;

    static {
        C2555a c2555a = new C2555a(67, 64, 1);
        f6967c = c2555a;
        f6968d = new C2555a(19, 16, 1);
        f6969e = new C2555a(285, 256, 0);
        C2555a c2555a2 = new C2555a(301, 256, 1);
        f6970f = c2555a2;
        f6971g = c2555a2;
        f6972h = c2555a;
    }

    public C2555a(int i2, int i3, int i4) {
        this.f6978n = i2;
        this.f6977m = i3;
        this.f6979o = i4;
        this.f6973i = new int[i3];
        this.f6974j = new int[i3];
        int i5 = 1;
        for (int i6 = 0; i6 < i3; i6++) {
            this.f6973i[i6] = i5;
            i5 <<= 1;
            if (i5 >= i3) {
                i5 = (i5 ^ i2) & (i3 - 1);
            }
        }
        for (int i7 = 0; i7 < i3 - 1; i7++) {
            this.f6974j[this.f6973i[i7]] = i7;
        }
        this.f6975k = new C2556b(this, new int[]{0});
        this.f6976l = new C2556b(this, new int[]{1});
    }

    /* renamed from: a */
    public C2556b m2975a(int i2, int i3) {
        if (i2 < 0) {
            throw new IllegalArgumentException();
        }
        if (i3 == 0) {
            return this.f6975k;
        }
        int[] iArr = new int[i2 + 1];
        iArr[0] = i3;
        return new C2556b(this, iArr);
    }

    /* renamed from: b */
    public int m2976b(int i2) {
        if (i2 != 0) {
            return this.f6973i[(this.f6977m - this.f6974j[i2]) - 1];
        }
        throw new ArithmeticException();
    }

    /* renamed from: c */
    public int m2977c(int i2, int i3) {
        if (i2 == 0 || i3 == 0) {
            return 0;
        }
        int[] iArr = this.f6973i;
        int[] iArr2 = this.f6974j;
        return iArr[(iArr2[i2] + iArr2[i3]) % (this.f6977m - 1)];
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("GF(0x");
        sb.append(Integer.toHexString(this.f6978n));
        sb.append(',');
        return C1499a.m579A(sb, this.f6977m, ')');
    }
}
