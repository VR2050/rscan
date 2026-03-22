package p005b.p199l.p266d.p274v;

import java.util.Arrays;

/* renamed from: b.l.d.v.a */
/* loaded from: classes2.dex */
public final class C2543a implements Cloneable {

    /* renamed from: c */
    public int[] f6891c;

    /* renamed from: e */
    public int f6892e;

    public C2543a() {
        this.f6892e = 0;
        this.f6891c = new int[1];
    }

    /* renamed from: a */
    public void m2946a(boolean z) {
        m2949f(this.f6892e + 1);
        if (z) {
            int[] iArr = this.f6891c;
            int i2 = this.f6892e;
            int i3 = i2 / 32;
            iArr[i3] = (1 << (i2 & 31)) | iArr[i3];
        }
        this.f6892e++;
    }

    /* renamed from: c */
    public void m2947c(C2543a c2543a) {
        int i2 = c2543a.f6892e;
        m2949f(this.f6892e + i2);
        for (int i3 = 0; i3 < i2; i3++) {
            m2946a(c2543a.m2950g(i3));
        }
    }

    public Object clone() {
        return new C2543a((int[]) this.f6891c.clone(), this.f6892e);
    }

    /* renamed from: d */
    public void m2948d(int i2, int i3) {
        if (i3 < 0 || i3 > 32) {
            throw new IllegalArgumentException("Num bits must be between 0 and 32");
        }
        m2949f(this.f6892e + i3);
        while (i3 > 0) {
            boolean z = true;
            if (((i2 >> (i3 - 1)) & 1) != 1) {
                z = false;
            }
            m2946a(z);
            i3--;
        }
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof C2543a)) {
            return false;
        }
        C2543a c2543a = (C2543a) obj;
        return this.f6892e == c2543a.f6892e && Arrays.equals(this.f6891c, c2543a.f6891c);
    }

    /* renamed from: f */
    public final void m2949f(int i2) {
        int[] iArr = this.f6891c;
        if (i2 > (iArr.length << 5)) {
            int[] iArr2 = new int[(i2 + 31) / 32];
            System.arraycopy(iArr, 0, iArr2, 0, iArr.length);
            this.f6891c = iArr2;
        }
    }

    /* renamed from: g */
    public boolean m2950g(int i2) {
        return ((1 << (i2 & 31)) & this.f6891c[i2 / 32]) != 0;
    }

    /* renamed from: h */
    public int m2951h(int i2) {
        int i3 = this.f6892e;
        if (i2 >= i3) {
            return i3;
        }
        int i4 = i2 / 32;
        int i5 = (-(1 << (i2 & 31))) & this.f6891c[i4];
        while (i5 == 0) {
            i4++;
            int[] iArr = this.f6891c;
            if (i4 == iArr.length) {
                return this.f6892e;
            }
            i5 = iArr[i4];
        }
        int numberOfTrailingZeros = Integer.numberOfTrailingZeros(i5) + (i4 << 5);
        int i6 = this.f6892e;
        return numberOfTrailingZeros > i6 ? i6 : numberOfTrailingZeros;
    }

    public int hashCode() {
        return Arrays.hashCode(this.f6891c) + (this.f6892e * 31);
    }

    /* renamed from: i */
    public int m2952i(int i2) {
        int i3 = this.f6892e;
        if (i2 >= i3) {
            return i3;
        }
        int i4 = i2 / 32;
        int i5 = (-(1 << (i2 & 31))) & (~this.f6891c[i4]);
        while (i5 == 0) {
            i4++;
            int[] iArr = this.f6891c;
            if (i4 == iArr.length) {
                return this.f6892e;
            }
            i5 = ~iArr[i4];
        }
        int numberOfTrailingZeros = Integer.numberOfTrailingZeros(i5) + (i4 << 5);
        int i6 = this.f6892e;
        return numberOfTrailingZeros > i6 ? i6 : numberOfTrailingZeros;
    }

    /* renamed from: j */
    public int m2953j() {
        return (this.f6892e + 7) / 8;
    }

    /* renamed from: l */
    public boolean m2954l(int i2, int i3, boolean z) {
        if (i3 < i2 || i2 < 0 || i3 > this.f6892e) {
            throw new IllegalArgumentException();
        }
        if (i3 == i2) {
            return true;
        }
        int i4 = i3 - 1;
        int i5 = i2 / 32;
        int i6 = i4 / 32;
        int i7 = i5;
        while (i7 <= i6) {
            int i8 = (2 << (i7 >= i6 ? 31 & i4 : 31)) - (1 << (i7 > i5 ? 0 : i2 & 31));
            int i9 = this.f6891c[i7] & i8;
            if (!z) {
                i8 = 0;
            }
            if (i9 != i8) {
                return false;
            }
            i7++;
        }
        return true;
    }

    /* renamed from: m */
    public void m2955m() {
        int[] iArr = new int[this.f6891c.length];
        int i2 = (this.f6892e - 1) / 32;
        int i3 = i2 + 1;
        for (int i4 = 0; i4 < i3; i4++) {
            long j2 = this.f6891c[i4];
            long j3 = ((j2 & 1431655765) << 1) | ((j2 >> 1) & 1431655765);
            long j4 = ((j3 & 858993459) << 2) | ((j3 >> 2) & 858993459);
            long j5 = ((j4 & 252645135) << 4) | ((j4 >> 4) & 252645135);
            long j6 = ((j5 & 16711935) << 8) | ((j5 >> 8) & 16711935);
            iArr[i2 - i4] = (int) (((j6 & 65535) << 16) | ((j6 >> 16) & 65535));
        }
        int i5 = this.f6892e;
        int i6 = i3 << 5;
        if (i5 != i6) {
            int i7 = i6 - i5;
            int i8 = iArr[0] >>> i7;
            for (int i9 = 1; i9 < i3; i9++) {
                int i10 = iArr[i9];
                iArr[i9 - 1] = i8 | (i10 << (32 - i7));
                i8 = i10 >>> i7;
            }
            iArr[i3 - 1] = i8;
        }
        this.f6891c = iArr;
    }

    /* renamed from: n */
    public void m2956n(int i2) {
        int[] iArr = this.f6891c;
        int i3 = i2 / 32;
        iArr[i3] = (1 << (i2 & 31)) | iArr[i3];
    }

    public String toString() {
        int i2 = this.f6892e;
        StringBuilder sb = new StringBuilder((i2 / 8) + i2 + 1);
        for (int i3 = 0; i3 < this.f6892e; i3++) {
            if ((i3 & 7) == 0) {
                sb.append(' ');
            }
            sb.append(m2950g(i3) ? 'X' : '.');
        }
        return sb.toString();
    }

    public C2543a(int i2) {
        this.f6892e = i2;
        this.f6891c = new int[(i2 + 31) / 32];
    }

    public C2543a(int[] iArr, int i2) {
        this.f6891c = iArr;
        this.f6892e = i2;
    }
}
