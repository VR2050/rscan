package p005b.p199l.p200a.p201a.p250p1;

import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.p1.s */
/* loaded from: classes.dex */
public final class C2359s {

    /* renamed from: a */
    public byte[] f6129a;

    /* renamed from: b */
    public int f6130b;

    /* renamed from: c */
    public int f6131c;

    /* renamed from: d */
    public int f6132d;

    public C2359s() {
        this.f6129a = C2344d0.f6040f;
    }

    /* renamed from: a */
    public final void m2553a() {
        int i2;
        int i3 = this.f6130b;
        C4195m.m4771I(i3 >= 0 && (i3 < (i2 = this.f6132d) || (i3 == i2 && this.f6131c == 0)));
    }

    /* renamed from: b */
    public int m2554b() {
        return ((this.f6132d - this.f6130b) * 8) - this.f6131c;
    }

    /* renamed from: c */
    public void m2555c() {
        if (this.f6131c == 0) {
            return;
        }
        this.f6131c = 0;
        this.f6130b++;
        m2553a();
    }

    /* renamed from: d */
    public int m2556d() {
        return (this.f6130b * 8) + this.f6131c;
    }

    /* renamed from: e */
    public boolean m2557e() {
        boolean z = (this.f6129a[this.f6130b] & (128 >> this.f6131c)) != 0;
        m2563k();
        return z;
    }

    /* renamed from: f */
    public int m2558f(int i2) {
        int i3;
        if (i2 == 0) {
            return 0;
        }
        this.f6131c += i2;
        int i4 = 0;
        while (true) {
            i3 = this.f6131c;
            if (i3 <= 8) {
                break;
            }
            int i5 = i3 - 8;
            this.f6131c = i5;
            byte[] bArr = this.f6129a;
            int i6 = this.f6130b;
            this.f6130b = i6 + 1;
            i4 |= (bArr[i6] & 255) << i5;
        }
        byte[] bArr2 = this.f6129a;
        int i7 = this.f6130b;
        int i8 = ((-1) >>> (32 - i2)) & (i4 | ((bArr2[i7] & 255) >> (8 - i3)));
        if (i3 == 8) {
            this.f6131c = 0;
            this.f6130b = i7 + 1;
        }
        m2553a();
        return i8;
    }

    /* renamed from: g */
    public void m2559g(byte[] bArr, int i2, int i3) {
        int i4 = (i3 >> 3) + i2;
        while (i2 < i4) {
            byte[] bArr2 = this.f6129a;
            int i5 = this.f6130b;
            int i6 = i5 + 1;
            this.f6130b = i6;
            byte b2 = bArr2[i5];
            int i7 = this.f6131c;
            bArr[i2] = (byte) (b2 << i7);
            bArr[i2] = (byte) (((255 & bArr2[i6]) >> (8 - i7)) | bArr[i2]);
            i2++;
        }
        int i8 = i3 & 7;
        if (i8 == 0) {
            return;
        }
        bArr[i4] = (byte) (bArr[i4] & (255 >> i8));
        int i9 = this.f6131c;
        if (i9 + i8 > 8) {
            int i10 = bArr[i4];
            byte[] bArr3 = this.f6129a;
            int i11 = this.f6130b;
            this.f6130b = i11 + 1;
            bArr[i4] = (byte) (i10 | ((bArr3[i11] & 255) << i9));
            this.f6131c = i9 - 8;
        }
        int i12 = this.f6131c + i8;
        this.f6131c = i12;
        byte[] bArr4 = this.f6129a;
        int i13 = this.f6130b;
        bArr[i4] = (byte) (((byte) (((255 & bArr4[i13]) >> (8 - i12)) << (8 - i8))) | bArr[i4]);
        if (i12 == 8) {
            this.f6131c = 0;
            this.f6130b = i13 + 1;
        }
        m2553a();
    }

    /* renamed from: h */
    public void m2560h(byte[] bArr, int i2, int i3) {
        C4195m.m4771I(this.f6131c == 0);
        System.arraycopy(this.f6129a, this.f6130b, bArr, i2, i3);
        this.f6130b += i3;
        m2553a();
    }

    /* renamed from: i */
    public void m2561i(byte[] bArr, int i2) {
        this.f6129a = bArr;
        this.f6130b = 0;
        this.f6131c = 0;
        this.f6132d = i2;
    }

    /* renamed from: j */
    public void m2562j(int i2) {
        int i3 = i2 / 8;
        this.f6130b = i3;
        this.f6131c = i2 - (i3 * 8);
        m2553a();
    }

    /* renamed from: k */
    public void m2563k() {
        int i2 = this.f6131c + 1;
        this.f6131c = i2;
        if (i2 == 8) {
            this.f6131c = 0;
            this.f6130b++;
        }
        m2553a();
    }

    /* renamed from: l */
    public void m2564l(int i2) {
        int i3 = i2 / 8;
        int i4 = this.f6130b + i3;
        this.f6130b = i4;
        int i5 = (i2 - (i3 * 8)) + this.f6131c;
        this.f6131c = i5;
        if (i5 > 7) {
            this.f6130b = i4 + 1;
            this.f6131c = i5 - 8;
        }
        m2553a();
    }

    public C2359s(byte[] bArr) {
        int length = bArr.length;
        this.f6129a = bArr;
        this.f6132d = length;
    }

    public C2359s(byte[] bArr, int i2) {
        this.f6129a = bArr;
        this.f6132d = i2;
    }
}
