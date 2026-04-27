package Q0;

import java.util.HashSet;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public abstract class v implements B {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Set f2393a = new HashSet();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final k f2394b = new k();

    private Object d(Object obj) {
        if (obj != null) {
            synchronized (this) {
                this.f2393a.remove(obj);
            }
        }
        return obj;
    }

    @Override // Q0.B
    public Object b() {
        return d(this.f2394b.f());
    }

    @Override // Q0.B
    public void c(Object obj) {
        boolean zAdd;
        synchronized (this) {
            zAdd = this.f2393a.add(obj);
        }
        if (zAdd) {
            this.f2394b.e(a(obj), obj);
        }
    }

    @Override // Q0.B
    public Object get(int i3) {
        return d(this.f2394b.a(i3));
    }
}
