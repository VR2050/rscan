package androidx.fragment.app;

import android.os.Bundle;
import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
class FragmentManager$6 implements androidx.lifecycle.i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final /* synthetic */ String f4835a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final /* synthetic */ androidx.lifecycle.f f4836b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final /* synthetic */ x f4837c;

    @Override // androidx.lifecycle.i
    public void d(androidx.lifecycle.k kVar, f.a aVar) {
        if (aVar == f.a.ON_START && ((Bundle) this.f4837c.f5053k.get(this.f4835a)) != null) {
            throw null;
        }
        if (aVar == f.a.ON_DESTROY) {
            this.f4836b.c(this);
            this.f4837c.f5054l.remove(this.f4835a);
        }
    }
}
