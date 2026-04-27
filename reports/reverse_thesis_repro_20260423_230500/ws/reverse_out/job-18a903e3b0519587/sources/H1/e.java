package H1;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d f1070a = new d();

    public final d a() {
        return this.f1070a;
    }

    public final void b() {
        if (!e()) {
            throw new IllegalStateException("Cannot cancel a completed task.");
        }
    }

    public final void c(Exception exc) {
        if (!f(exc)) {
            throw new IllegalStateException("Cannot set the error on a completed task.");
        }
    }

    public final void d(Object obj) {
        if (!g(obj)) {
            throw new IllegalStateException("Cannot set the result of a completed task.");
        }
    }

    public final boolean e() {
        return this.f1070a.x();
    }

    public final boolean f(Exception exc) {
        return this.f1070a.y(exc);
    }

    public final boolean g(Object obj) {
        return this.f1070a.z(obj);
    }
}
