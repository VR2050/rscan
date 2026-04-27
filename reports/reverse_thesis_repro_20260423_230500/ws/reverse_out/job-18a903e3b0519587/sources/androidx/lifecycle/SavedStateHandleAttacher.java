package androidx.lifecycle;

import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
public final class SavedStateHandleAttacher implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final w f5123a;

    public SavedStateHandleAttacher(w wVar) {
        t2.j.f(wVar, "provider");
        this.f5123a = wVar;
    }

    @Override // androidx.lifecycle.i
    public void d(k kVar, f.a aVar) {
        t2.j.f(kVar, "source");
        t2.j.f(aVar, "event");
        if (aVar == f.a.ON_CREATE) {
            kVar.s().c(this);
            this.f5123a.c();
        } else {
            throw new IllegalStateException(("Next event must be ON_CREATE, it was " + aVar).toString());
        }
    }
}
