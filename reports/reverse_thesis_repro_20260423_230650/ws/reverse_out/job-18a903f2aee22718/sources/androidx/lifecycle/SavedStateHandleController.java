package androidx.lifecycle;

import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
public final class SavedStateHandleController implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f5124a;

    @Override // androidx.lifecycle.i
    public void d(k kVar, f.a aVar) {
        t2.j.f(kVar, "source");
        t2.j.f(aVar, "event");
        if (aVar == f.a.ON_DESTROY) {
            this.f5124a = false;
            kVar.s().c(this);
        }
    }

    public final void h(androidx.savedstate.a aVar, f fVar) {
        t2.j.f(aVar, "registry");
        t2.j.f(fVar, "lifecycle");
        if (this.f5124a) {
            throw new IllegalStateException("Already attached to lifecycleOwner");
        }
        this.f5124a = true;
        fVar.a(this);
        throw null;
    }

    public final boolean i() {
        return this.f5124a;
    }
}
