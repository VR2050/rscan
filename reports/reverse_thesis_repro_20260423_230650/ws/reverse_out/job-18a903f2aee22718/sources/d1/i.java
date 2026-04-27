package d1;

/* JADX INFO: loaded from: classes.dex */
public final class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Thread f9175a;

    public final void a() {
        Thread threadCurrentThread = Thread.currentThread();
        if (this.f9175a == null) {
            this.f9175a = threadCurrentThread;
        }
        Z0.a.a(t2.j.b(this.f9175a, threadCurrentThread));
    }
}
