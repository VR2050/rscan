package p005b.p199l.p266d;

/* renamed from: b.l.d.m */
/* loaded from: classes2.dex */
public final class C2531m extends AbstractC2527i {

    /* renamed from: c */
    public final byte[] f6849c;

    /* renamed from: d */
    public final int f6850d;

    /* renamed from: e */
    public final int f6851e;

    public C2531m(int i2, int i3, int[] iArr) {
        super(i2, i3);
        this.f6850d = i2;
        this.f6851e = i3;
        int i4 = i2 * i3;
        this.f6849c = new byte[i4];
        for (int i5 = 0; i5 < i4; i5++) {
            int i6 = iArr[i5];
            this.f6849c[i5] = (byte) (((((i6 >> 16) & 255) + ((i6 >> 7) & 510)) + (i6 & 255)) / 4);
        }
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: a */
    public byte[] mo2926a() {
        int i2 = this.f6838a;
        int i3 = this.f6839b;
        int i4 = this.f6850d;
        if (i2 == i4 && i3 == this.f6851e) {
            return this.f6849c;
        }
        int i5 = i2 * i3;
        byte[] bArr = new byte[i5];
        int i6 = (0 * i4) + 0;
        if (i2 == i4) {
            System.arraycopy(this.f6849c, i6, bArr, 0, i5);
            return bArr;
        }
        for (int i7 = 0; i7 < i3; i7++) {
            System.arraycopy(this.f6849c, i6, bArr, i7 * i2, i2);
            i6 += this.f6850d;
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
        System.arraycopy(this.f6849c, ((i2 + 0) * this.f6850d) + 0, bArr, 0, i3);
        return bArr;
    }
}
