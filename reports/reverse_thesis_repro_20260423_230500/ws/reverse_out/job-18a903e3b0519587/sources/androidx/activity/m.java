package androidx.activity;

import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public abstract class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f2997a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final CopyOnWriteArrayList f2998b = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private InterfaceC0688a f2999c;

    public m(boolean z3) {
        this.f2997a = z3;
    }

    public final void a(a aVar) {
        t2.j.f(aVar, "cancellable");
        this.f2998b.add(aVar);
    }

    public abstract void b();

    public final boolean c() {
        return this.f2997a;
    }

    public final void d() {
        Iterator it = this.f2998b.iterator();
        while (it.hasNext()) {
            ((a) it.next()).cancel();
        }
    }

    public final void e(a aVar) {
        t2.j.f(aVar, "cancellable");
        this.f2998b.remove(aVar);
    }

    public final void f(boolean z3) {
        this.f2997a = z3;
        InterfaceC0688a interfaceC0688a = this.f2999c;
        if (interfaceC0688a != null) {
            interfaceC0688a.a();
        }
    }

    public final void g(InterfaceC0688a interfaceC0688a) {
        this.f2999c = interfaceC0688a;
    }
}
