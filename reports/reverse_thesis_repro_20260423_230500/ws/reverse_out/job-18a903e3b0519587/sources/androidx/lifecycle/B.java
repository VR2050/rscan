package androidx.lifecycle;

import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public class B {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f5093a = new LinkedHashMap();

    public final void a() {
        Iterator it = this.f5093a.values().iterator();
        while (it.hasNext()) {
            ((y) it.next()).a();
        }
        this.f5093a.clear();
    }

    public final y b(String str) {
        t2.j.f(str, "key");
        return (y) this.f5093a.get(str);
    }

    public final Set c() {
        return new HashSet(this.f5093a.keySet());
    }

    public final void d(String str, y yVar) {
        t2.j.f(str, "key");
        t2.j.f(yVar, "viewModel");
        y yVar2 = (y) this.f5093a.put(str, yVar);
        if (yVar2 != null) {
            yVar2.d();
        }
    }
}
