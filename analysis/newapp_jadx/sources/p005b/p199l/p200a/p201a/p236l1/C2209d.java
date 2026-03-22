package p005b.p199l.p200a.p201a.p236l1;

/* renamed from: b.l.a.a.l1.d */
/* loaded from: classes.dex */
public final class C2209d extends AbstractC2215j {

    /* renamed from: f */
    public final AbstractC2208c f5289f;

    public C2209d(AbstractC2208c abstractC2208c) {
        this.f5289f = abstractC2208c;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.AbstractC1946f
    public final void release() {
        AbstractC2208c abstractC2208c = this.f5289f;
        synchronized (abstractC2208c.f3311b) {
            clear();
            O[] oArr = abstractC2208c.f3315f;
            int i2 = abstractC2208c.f3317h;
            abstractC2208c.f3317h = i2 + 1;
            oArr[i2] = this;
            abstractC2208c.m1385g();
        }
    }
}
