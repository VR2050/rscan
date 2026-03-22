package p005b.p199l.p266d.p274v;

import java.util.Arrays;

/* renamed from: b.l.d.v.b */
/* loaded from: classes2.dex */
public final class C2544b implements Cloneable {

    /* renamed from: c */
    public final int f6893c;

    /* renamed from: e */
    public final int f6894e;

    /* renamed from: f */
    public final int f6895f;

    /* renamed from: g */
    public final int[] f6896g;

    public C2544b(int i2, int i3) {
        if (i2 <= 0 || i3 <= 0) {
            throw new IllegalArgumentException("Both dimensions must be greater than 0");
        }
        this.f6893c = i2;
        this.f6894e = i3;
        int i4 = (i2 + 31) / 32;
        this.f6895f = i4;
        this.f6896g = new int[i4 * i3];
    }

    /* renamed from: a */
    public void m2957a(int i2, int i3) {
        int i4 = (i2 / 32) + (i3 * this.f6895f);
        int[] iArr = this.f6896g;
        iArr[i4] = (1 << (i2 & 31)) ^ iArr[i4];
    }

    /* renamed from: c */
    public boolean m2958c(int i2, int i3) {
        return ((this.f6896g[(i2 / 32) + (i3 * this.f6895f)] >>> (i2 & 31)) & 1) != 0;
    }

    public Object clone() {
        return new C2544b(this.f6893c, this.f6894e, this.f6895f, (int[]) this.f6896g.clone());
    }

    /* renamed from: d */
    public int[] m2959d() {
        int length = this.f6896g.length - 1;
        while (length >= 0 && this.f6896g[length] == 0) {
            length--;
        }
        if (length < 0) {
            return null;
        }
        int i2 = this.f6895f;
        int i3 = length / i2;
        int i4 = (length % i2) << 5;
        int i5 = 31;
        while ((this.f6896g[length] >>> i5) == 0) {
            i5--;
        }
        return new int[]{i4 + i5, i3};
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof C2544b)) {
            return false;
        }
        C2544b c2544b = (C2544b) obj;
        return this.f6893c == c2544b.f6893c && this.f6894e == c2544b.f6894e && this.f6895f == c2544b.f6895f && Arrays.equals(this.f6896g, c2544b.f6896g);
    }

    /* renamed from: f */
    public C2543a m2960f(int i2, C2543a c2543a) {
        int i3 = c2543a.f6892e;
        int i4 = this.f6893c;
        if (i3 < i4) {
            c2543a = new C2543a(i4);
        } else {
            int length = c2543a.f6891c.length;
            for (int i5 = 0; i5 < length; i5++) {
                c2543a.f6891c[i5] = 0;
            }
        }
        int i6 = i2 * this.f6895f;
        for (int i7 = 0; i7 < this.f6895f; i7++) {
            c2543a.f6891c[(i7 << 5) / 32] = this.f6896g[i6 + i7];
        }
        return c2543a;
    }

    /* renamed from: g */
    public int[] m2961g() {
        int[] iArr;
        int i2 = 0;
        while (true) {
            iArr = this.f6896g;
            if (i2 >= iArr.length || iArr[i2] != 0) {
                break;
            }
            i2++;
        }
        if (i2 == iArr.length) {
            return null;
        }
        int i3 = this.f6895f;
        int i4 = i2 / i3;
        int i5 = (i2 % i3) << 5;
        int i6 = iArr[i2];
        int i7 = 0;
        while ((i6 << (31 - i7)) == 0) {
            i7++;
        }
        return new int[]{i5 + i7, i4};
    }

    /* renamed from: h */
    public void m2962h(int i2, int i3) {
        int i4 = (i2 / 32) + (i3 * this.f6895f);
        int[] iArr = this.f6896g;
        iArr[i4] = (1 << (i2 & 31)) | iArr[i4];
    }

    public int hashCode() {
        int i2 = this.f6893c;
        return Arrays.hashCode(this.f6896g) + (((((((i2 * 31) + i2) * 31) + this.f6894e) * 31) + this.f6895f) * 31);
    }

    /* renamed from: i */
    public void m2963i(int i2, int i3, int i4, int i5) {
        if (i3 < 0 || i2 < 0) {
            throw new IllegalArgumentException("Left and top must be nonnegative");
        }
        if (i5 <= 0 || i4 <= 0) {
            throw new IllegalArgumentException("Height and width must be at least 1");
        }
        int i6 = i4 + i2;
        int i7 = i5 + i3;
        if (i7 > this.f6894e || i6 > this.f6893c) {
            throw new IllegalArgumentException("The region must fit inside the matrix");
        }
        while (i3 < i7) {
            int i8 = this.f6895f * i3;
            for (int i9 = i2; i9 < i6; i9++) {
                int[] iArr = this.f6896g;
                int i10 = (i9 / 32) + i8;
                iArr[i10] = iArr[i10] | (1 << (i9 & 31));
            }
            i3++;
        }
    }

    public String toString() {
        StringBuilder sb = new StringBuilder((this.f6893c + 1) * this.f6894e);
        for (int i2 = 0; i2 < this.f6894e; i2++) {
            for (int i3 = 0; i3 < this.f6893c; i3++) {
                sb.append(m2958c(i3, i2) ? "X " : "  ");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public C2544b(int i2, int i3, int i4, int[] iArr) {
        this.f6893c = i2;
        this.f6894e = i3;
        this.f6895f = i4;
        this.f6896g = iArr;
    }
}
