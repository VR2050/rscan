package p005b.p143g.p144a.p170s.p171j;

/* renamed from: b.g.a.s.j.d */
/* loaded from: classes.dex */
public abstract class AbstractC1811d {

    /* renamed from: b.g.a.s.j.d$b */
    public static class b extends AbstractC1811d {

        /* renamed from: a */
        public volatile boolean f2774a;

        public b() {
            super(null);
        }

        @Override // p005b.p143g.p144a.p170s.p171j.AbstractC1811d
        /* renamed from: a */
        public void mo1155a() {
            if (this.f2774a) {
                throw new IllegalStateException("Already released");
            }
        }
    }

    public AbstractC1811d(a aVar) {
    }

    /* renamed from: a */
    public abstract void mo1155a();
}
