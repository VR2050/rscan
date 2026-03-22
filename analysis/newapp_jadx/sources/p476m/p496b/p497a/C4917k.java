package p476m.p496b.p497a;

/* renamed from: m.b.a.k */
/* loaded from: classes3.dex */
public final class C4917k {

    /* renamed from: a */
    public C4916j f12548a;

    /* renamed from: b */
    public C4916j f12549b;

    /* renamed from: a */
    public synchronized void m5585a(C4916j c4916j) {
        C4916j c4916j2 = this.f12549b;
        if (c4916j2 != null) {
            c4916j2.f12547d = c4916j;
            this.f12549b = c4916j;
        } else {
            if (this.f12548a != null) {
                throw new IllegalStateException("Head present, but no tail");
            }
            this.f12549b = c4916j;
            this.f12548a = c4916j;
        }
        notifyAll();
    }

    /* renamed from: b */
    public synchronized C4916j m5586b() {
        C4916j c4916j;
        c4916j = this.f12548a;
        if (c4916j != null) {
            C4916j c4916j2 = c4916j.f12547d;
            this.f12548a = c4916j2;
            if (c4916j2 == null) {
                this.f12549b = null;
            }
        }
        return c4916j;
    }
}
