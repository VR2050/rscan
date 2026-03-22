package p005b.p199l.p266d;

/* renamed from: b.l.d.l */
/* loaded from: classes2.dex */
public final class C2530l extends AbstractC2527i {

    /* renamed from: c */
    public final byte[] f6844c;

    /* renamed from: d */
    public final int f6845d;

    /* renamed from: e */
    public final int f6846e;

    /* renamed from: f */
    public final int f6847f;

    /* renamed from: g */
    public final int f6848g;

    public C2530l(byte[] bArr, int i2, int i3, int i4, int i5, int i6, int i7, boolean z) {
        super(i6, i7);
        if (i4 + i6 > i2 || i5 + i7 > i3) {
            throw new IllegalArgumentException("Crop rectangle does not fit within image data.");
        }
        this.f6844c = bArr;
        this.f6845d = i2;
        this.f6846e = i3;
        this.f6847f = i4;
        this.f6848g = i5;
        if (z) {
            int i8 = (i5 * i2) + i4;
            int i9 = 0;
            while (i9 < i7) {
                int i10 = (i6 / 2) + i8;
                int i11 = (i8 + i6) - 1;
                int i12 = i8;
                while (i12 < i10) {
                    byte b2 = bArr[i12];
                    bArr[i12] = bArr[i11];
                    bArr[i11] = b2;
                    i12++;
                    i11--;
                }
                i9++;
                i8 += this.f6845d;
            }
        }
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: a */
    public byte[] mo2926a() {
        int i2 = this.f6838a;
        int i3 = this.f6839b;
        int i4 = this.f6845d;
        if (i2 == i4 && i3 == this.f6846e) {
            return this.f6844c;
        }
        int i5 = i2 * i3;
        byte[] bArr = new byte[i5];
        int i6 = (this.f6848g * i4) + this.f6847f;
        if (i2 == i4) {
            System.arraycopy(this.f6844c, i6, bArr, 0, i5);
            return bArr;
        }
        for (int i7 = 0; i7 < i3; i7++) {
            System.arraycopy(this.f6844c, i6, bArr, i7 * i2, i2);
            i6 += this.f6845d;
        }
        return bArr;
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: b */
    public byte[] mo2927b(int i2, byte[] bArr) {
        if (i2 < 0 || i2 >= this.f6839b) {
            throw new IllegalArgumentException("Requested row is outside the image: ".concat(String.valueOf(i2)));
        }
        int i3 = this.f6838a;
        if (bArr == null || bArr.length < i3) {
            bArr = new byte[i3];
        }
        System.arraycopy(this.f6844c, ((i2 + this.f6848g) * this.f6845d) + this.f6847f, bArr, 0, i3);
        return bArr;
    }
}
