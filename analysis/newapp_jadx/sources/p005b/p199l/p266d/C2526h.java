package p005b.p199l.p266d;

/* renamed from: b.l.d.h */
/* loaded from: classes2.dex */
public final class C2526h extends AbstractC2527i {

    /* renamed from: c */
    public final AbstractC2527i f6837c;

    public C2526h(AbstractC2527i abstractC2527i) {
        super(abstractC2527i.f6838a, abstractC2527i.f6839b);
        this.f6837c = abstractC2527i;
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: a */
    public byte[] mo2926a() {
        byte[] mo2926a = this.f6837c.mo2926a();
        int i2 = this.f6838a * this.f6839b;
        byte[] bArr = new byte[i2];
        for (int i3 = 0; i3 < i2; i3++) {
            bArr[i3] = (byte) (255 - (mo2926a[i3] & 255));
        }
        return bArr;
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: b */
    public byte[] mo2927b(int i2, byte[] bArr) {
        byte[] mo2927b = this.f6837c.mo2927b(i2, bArr);
        int i3 = this.f6838a;
        for (int i4 = 0; i4 < i3; i4++) {
            mo2927b[i4] = (byte) (255 - (mo2927b[i4] & 255));
        }
        return mo2927b;
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: c */
    public boolean mo2928c() {
        return this.f6837c.mo2928c();
    }

    @Override // p005b.p199l.p266d.AbstractC2527i
    /* renamed from: d */
    public AbstractC2527i mo2929d() {
        return new C2526h(this.f6837c.mo2929d());
    }
}
