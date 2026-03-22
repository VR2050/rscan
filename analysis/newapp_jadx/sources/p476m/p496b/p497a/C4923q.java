package p476m.p496b.p497a;

/* renamed from: m.b.a.q */
/* loaded from: classes3.dex */
public final class C4923q {

    /* renamed from: a */
    public final Object f12568a;

    /* renamed from: b */
    public final C4921o f12569b;

    /* renamed from: c */
    public volatile boolean f12570c = true;

    public C4923q(Object obj, C4921o c4921o) {
        this.f12568a = obj;
        this.f12569b = c4921o;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof C4923q)) {
            return false;
        }
        C4923q c4923q = (C4923q) obj;
        return this.f12568a == c4923q.f12568a && this.f12569b.equals(c4923q.f12569b);
    }

    public int hashCode() {
        return this.f12569b.f12558f.hashCode() + this.f12568a.hashCode();
    }
}
