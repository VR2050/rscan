package G2;

import B2.F;
import java.util.LinkedHashSet;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public final class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Set f961a = new LinkedHashSet();

    public final synchronized void a(F f3) {
        t2.j.f(f3, "route");
        this.f961a.remove(f3);
    }

    public final synchronized void b(F f3) {
        t2.j.f(f3, "failedRoute");
        this.f961a.add(f3);
    }

    public final synchronized boolean c(F f3) {
        t2.j.f(f3, "route");
        return this.f961a.contains(f3);
    }
}
