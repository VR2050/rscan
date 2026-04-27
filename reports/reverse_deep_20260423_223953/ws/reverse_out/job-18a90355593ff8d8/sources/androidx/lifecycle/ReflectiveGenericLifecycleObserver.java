package androidx.lifecycle;

import androidx.lifecycle.C0303a;
import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
@Deprecated
class ReflectiveGenericLifecycleObserver implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object f5121a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0303a.C0073a f5122b;

    ReflectiveGenericLifecycleObserver(Object obj) {
        this.f5121a = obj;
        this.f5122b = C0303a.f5125c.c(obj.getClass());
    }

    @Override // androidx.lifecycle.i
    public void d(k kVar, f.a aVar) {
        this.f5122b.a(kVar, aVar, this.f5121a);
    }
}
