package E;

import E.a;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends a {
    /* JADX WARN: Multi-variable type inference failed */
    public d() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public final void b(a.b bVar, Object obj) {
        j.f(bVar, "key");
        a().put(bVar, obj);
    }

    public d(a aVar) {
        j.f(aVar, "initialExtras");
        a().putAll(aVar.a());
    }

    public /* synthetic */ d(a aVar, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? a.C0012a.f610b : aVar);
    }
}
