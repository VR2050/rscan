package p476m.p496b.p497a;

/* renamed from: m.b.a.a */
/* loaded from: classes3.dex */
public class RunnableC4907a implements Runnable, InterfaceC4918l {

    /* renamed from: c */
    public final C4917k f12503c = new C4917k();

    /* renamed from: e */
    public final C4909c f12504e;

    public RunnableC4907a(C4909c c4909c) {
        this.f12504e = c4909c;
    }

    @Override // p476m.p496b.p497a.InterfaceC4918l
    /* renamed from: a */
    public void mo5567a(C4923q c4923q, Object obj) {
        this.f12503c.m5585a(C4916j.m5584a(c4923q, obj));
        this.f12504e.f12520m.execute(this);
    }

    @Override // java.lang.Runnable
    public void run() {
        C4916j m5586b = this.f12503c.m5586b();
        if (m5586b == null) {
            throw new IllegalStateException("No pending post available");
        }
        this.f12504e.m5570c(m5586b);
    }
}
