package androidx.lifecycle;

import androidx.lifecycle.f;
import l2.InterfaceC0622a;

/* JADX INFO: loaded from: classes.dex */
public final class LifecycleCoroutineScopeImpl extends g implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final f f5101a;

    @Override // androidx.lifecycle.i
    public void d(k kVar, f.a aVar) {
        t2.j.f(kVar, "source");
        t2.j.f(aVar, "event");
        if (i().b().compareTo(f.b.DESTROYED) <= 0) {
            i().c(this);
            h();
            A2.c.b(null, null, 1, null);
        }
    }

    public InterfaceC0622a h() {
        return null;
    }

    public f i() {
        return this.f5101a;
    }
}
