package Q2;

import i2.AbstractC0580h;

/* JADX INFO: loaded from: classes.dex */
public final class C extends l {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final transient byte[][] f2519g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final transient int[] f2520h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(byte[][] bArr, int[] iArr) {
        super(l.f2555e.g());
        t2.j.f(bArr, "segments");
        t2.j.f(iArr, "directory");
        this.f2519g = bArr;
        this.f2520h = iArr;
    }

    private final l D() {
        return new l(y());
    }

    @Override // Q2.l
    public void A(i iVar, int i3, int i4) {
        t2.j.f(iVar, "buffer");
        int i5 = i3 + i4;
        int iB = R2.e.b(this, i3);
        while (i3 < i5) {
            int i6 = iB == 0 ? 0 : B()[iB - 1];
            int i7 = B()[iB] - i6;
            int i8 = B()[C().length + iB];
            int iMin = Math.min(i5, i7 + i6) - i3;
            int i9 = i8 + (i3 - i6);
            A a3 = new A(C()[iB], i9, i9 + iMin, true, false);
            A a4 = iVar.f2544b;
            if (a4 == null) {
                a3.f2513g = a3;
                a3.f2512f = a3;
                iVar.f2544b = a3;
            } else {
                t2.j.c(a4);
                A a5 = a4.f2513g;
                t2.j.c(a5);
                a5.c(a3);
            }
            i3 += iMin;
            iB++;
        }
        iVar.E0(iVar.F0() + ((long) i4));
    }

    public final int[] B() {
        return this.f2520h;
    }

    public final byte[][] C() {
        return this.f2519g;
    }

    @Override // Q2.l
    public String a() {
        return D().a();
    }

    @Override // Q2.l
    public l d(String str) {
        t2.j.f(str, "algorithm");
        return R2.b.e(this, str);
    }

    @Override // Q2.l
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof l) {
            l lVar = (l) obj;
            if (lVar.v() == v() && p(0, lVar, 0, v())) {
                return true;
            }
        }
        return false;
    }

    @Override // Q2.l
    public int hashCode() {
        int iH = h();
        if (iH != 0) {
            return iH;
        }
        int length = C().length;
        int i3 = 0;
        int i4 = 1;
        int i5 = 0;
        while (i3 < length) {
            int i6 = B()[length + i3];
            int i7 = B()[i3];
            byte[] bArr = C()[i3];
            int i8 = (i7 - i5) + i6;
            while (i6 < i8) {
                i4 = (i4 * 31) + bArr[i6];
                i6++;
            }
            i3++;
            i5 = i7;
        }
        r(i4);
        return i4;
    }

    @Override // Q2.l
    public int i() {
        return B()[C().length - 1];
    }

    @Override // Q2.l
    public String k() {
        return D().k();
    }

    @Override // Q2.l
    public byte[] l() {
        return y();
    }

    @Override // Q2.l
    public byte m(int i3) {
        AbstractC0210f.b(B()[C().length - 1], i3, 1L);
        int iB = R2.e.b(this, i3);
        return C()[iB][(i3 - (iB == 0 ? 0 : B()[iB - 1])) + B()[C().length + iB]];
    }

    @Override // Q2.l
    public boolean p(int i3, l lVar, int i4, int i5) {
        t2.j.f(lVar, "other");
        if (i3 < 0 || i3 > v() - i5) {
            return false;
        }
        int i6 = i5 + i3;
        int iB = R2.e.b(this, i3);
        while (i3 < i6) {
            int i7 = iB == 0 ? 0 : B()[iB - 1];
            int i8 = B()[iB] - i7;
            int i9 = B()[C().length + iB];
            int iMin = Math.min(i6, i8 + i7) - i3;
            if (!lVar.q(i4, C()[iB], i9 + (i3 - i7), iMin)) {
                return false;
            }
            i4 += iMin;
            i3 += iMin;
            iB++;
        }
        return true;
    }

    @Override // Q2.l
    public boolean q(int i3, byte[] bArr, int i4, int i5) {
        t2.j.f(bArr, "other");
        if (i3 < 0 || i3 > v() - i5 || i4 < 0 || i4 > bArr.length - i5) {
            return false;
        }
        int i6 = i5 + i3;
        int iB = R2.e.b(this, i3);
        while (i3 < i6) {
            int i7 = iB == 0 ? 0 : B()[iB - 1];
            int i8 = B()[iB] - i7;
            int i9 = B()[C().length + iB];
            int iMin = Math.min(i6, i8 + i7) - i3;
            if (!AbstractC0210f.a(C()[iB], i9 + (i3 - i7), bArr, i4, iMin)) {
                return false;
            }
            i4 += iMin;
            i3 += iMin;
            iB++;
        }
        return true;
    }

    @Override // Q2.l
    public String toString() {
        return D().toString();
    }

    @Override // Q2.l
    public l x() {
        return D().x();
    }

    @Override // Q2.l
    public byte[] y() {
        byte[] bArr = new byte[v()];
        int length = C().length;
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        while (i3 < length) {
            int i6 = B()[length + i3];
            int i7 = B()[i3];
            int i8 = i7 - i4;
            AbstractC0580h.e(C()[i3], bArr, i5, i6, i6 + i8);
            i5 += i8;
            i3++;
            i4 = i7;
        }
        return bArr;
    }
}
