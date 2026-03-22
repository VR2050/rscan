package p005b.p199l.p266d;

/* renamed from: b.l.d.i */
/* loaded from: classes2.dex */
public abstract class AbstractC2527i {

    /* renamed from: a */
    public final int f6838a;

    /* renamed from: b */
    public final int f6839b;

    public AbstractC2527i(int i2, int i3) {
        this.f6838a = i2;
        this.f6839b = i3;
    }

    /* renamed from: a */
    public abstract byte[] mo2926a();

    /* renamed from: b */
    public abstract byte[] mo2927b(int i2, byte[] bArr);

    /* renamed from: c */
    public boolean mo2928c() {
        return false;
    }

    /* renamed from: d */
    public AbstractC2527i mo2929d() {
        throw new UnsupportedOperationException("This luminance source does not support rotation by 90 degrees.");
    }

    public final String toString() {
        int i2 = this.f6838a;
        byte[] bArr = new byte[i2];
        StringBuilder sb = new StringBuilder((i2 + 1) * this.f6839b);
        for (int i3 = 0; i3 < this.f6839b; i3++) {
            bArr = mo2927b(i3, bArr);
            for (int i4 = 0; i4 < this.f6838a; i4++) {
                int i5 = bArr[i4] & 255;
                sb.append(i5 < 64 ? '#' : i5 < 128 ? '+' : i5 < 192 ? '.' : ' ');
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
