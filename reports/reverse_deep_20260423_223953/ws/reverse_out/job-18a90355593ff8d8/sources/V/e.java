package V;

import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes.dex */
public abstract class e implements Runnable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected final AtomicInteger f2808b = new AtomicInteger(0);

    public void a() {
        if (this.f2808b.compareAndSet(0, 2)) {
            d();
        }
    }

    protected abstract void b(Object obj);

    protected abstract Object c();

    protected abstract void d();

    protected abstract void e(Exception exc);

    protected abstract void f(Object obj);

    @Override // java.lang.Runnable
    public final void run() {
        if (this.f2808b.compareAndSet(0, 1)) {
            try {
                Object objC = c();
                this.f2808b.set(3);
                try {
                    f(objC);
                } finally {
                    b(objC);
                }
            } catch (Exception e3) {
                this.f2808b.set(4);
                e(e3);
            }
        }
    }
}
