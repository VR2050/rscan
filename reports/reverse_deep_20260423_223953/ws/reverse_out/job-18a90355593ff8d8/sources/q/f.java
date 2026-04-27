package q;

import androidx.core.util.Pools$SimplePool;

/* JADX INFO: loaded from: classes.dex */
public class f extends Pools$SimplePool {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Object f9846c;

    public f(int i3) {
        super(i3);
        this.f9846c = new Object();
    }

    @Override // androidx.core.util.Pools$SimplePool, q.e
    public boolean a(Object obj) {
        boolean zA;
        t2.j.f(obj, "instance");
        synchronized (this.f9846c) {
            zA = super.a(obj);
        }
        return zA;
    }

    @Override // androidx.core.util.Pools$SimplePool, q.e
    public Object b() {
        Object objB;
        synchronized (this.f9846c) {
            objB = super.b();
        }
        return objB;
    }
}
