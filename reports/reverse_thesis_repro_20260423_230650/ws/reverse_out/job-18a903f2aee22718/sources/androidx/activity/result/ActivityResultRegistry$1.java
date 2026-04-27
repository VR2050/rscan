package androidx.activity.result;

import androidx.activity.result.e;
import androidx.lifecycle.f;
import androidx.lifecycle.i;
import androidx.lifecycle.k;
import b.AbstractC0308a;

/* JADX INFO: loaded from: classes.dex */
class ActivityResultRegistry$1 implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final /* synthetic */ String f3003a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final /* synthetic */ b f3004b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final /* synthetic */ AbstractC0308a f3005c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    final /* synthetic */ e f3006d;

    @Override // androidx.lifecycle.i
    public void d(k kVar, f.a aVar) {
        if (!f.a.ON_START.equals(aVar)) {
            if (f.a.ON_STOP.equals(aVar)) {
                this.f3006d.f3014f.remove(this.f3003a);
                return;
            } else {
                if (f.a.ON_DESTROY.equals(aVar)) {
                    this.f3006d.i(this.f3003a);
                    return;
                }
                return;
            }
        }
        this.f3006d.f3014f.put(this.f3003a, new e.b(this.f3004b, this.f3005c));
        if (this.f3006d.f3015g.containsKey(this.f3003a)) {
            Object obj = this.f3006d.f3015g.get(this.f3003a);
            this.f3006d.f3015g.remove(this.f3003a);
            this.f3004b.a(obj);
        }
        a aVar2 = (a) this.f3006d.f3016h.getParcelable(this.f3003a);
        if (aVar2 != null) {
            this.f3006d.f3016h.remove(this.f3003a);
            this.f3004b.a(this.f3005c.a(aVar2.b(), aVar2.a()));
        }
    }
}
