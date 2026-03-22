package p005b.p199l.p266d.p274v;

/* renamed from: b.l.d.v.c */
/* loaded from: classes2.dex */
public final class C2545c {

    /* renamed from: a */
    public final byte[] f6897a;

    /* renamed from: b */
    public int f6898b;

    /* renamed from: c */
    public int f6899c;

    public C2545c(byte[] bArr) {
        this.f6897a = bArr;
    }

    /* renamed from: a */
    public int m2964a() {
        return ((this.f6897a.length - this.f6898b) * 8) - this.f6899c;
    }

    /* renamed from: b */
    public int m2965b(int i2) {
        if (i2 <= 0 || i2 > 32 || i2 > m2964a()) {
            throw new IllegalArgumentException(String.valueOf(i2));
        }
        int i3 = this.f6899c;
        int i4 = 0;
        if (i3 > 0) {
            int i5 = 8 - i3;
            int i6 = i2 < i5 ? i2 : i5;
            int i7 = i5 - i6;
            byte[] bArr = this.f6897a;
            int i8 = this.f6898b;
            int i9 = (((255 >> (8 - i6)) << i7) & bArr[i8]) >> i7;
            i2 -= i6;
            int i10 = i3 + i6;
            this.f6899c = i10;
            if (i10 == 8) {
                this.f6899c = 0;
                this.f6898b = i8 + 1;
            }
            i4 = i9;
        }
        if (i2 <= 0) {
            return i4;
        }
        while (i2 >= 8) {
            int i11 = i4 << 8;
            byte[] bArr2 = this.f6897a;
            int i12 = this.f6898b;
            i4 = (bArr2[i12] & 255) | i11;
            this.f6898b = i12 + 1;
            i2 -= 8;
        }
        if (i2 <= 0) {
            return i4;
        }
        int i13 = 8 - i2;
        int i14 = (i4 << i2) | ((((255 >> i13) << i13) & this.f6897a[this.f6898b]) >> i13);
        this.f6899c += i2;
        return i14;
    }
}
