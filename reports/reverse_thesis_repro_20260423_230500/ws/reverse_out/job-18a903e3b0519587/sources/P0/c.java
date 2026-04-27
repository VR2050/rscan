package P0;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public class c implements e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f2154a;

    public c(Set set) {
        this.f2154a = new ArrayList(set.size());
        Iterator it = set.iterator();
        while (it.hasNext()) {
            e eVar = (e) it.next();
            if (eVar != null) {
                this.f2154a.add(eVar);
            }
        }
    }

    private void l(String str, Throwable th) {
        Y.a.n("ForwardingRequestListener", str, th);
    }

    @Override // P0.e
    public void a(T0.b bVar, String str, Throwable th, boolean z3) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).a(bVar, str, th, z3);
            } catch (Exception e3) {
                l("InternalListener exception in onRequestFailure", e3);
            }
        }
    }

    @Override // P0.e
    public void b(T0.b bVar, Object obj, String str, boolean z3) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).b(bVar, obj, str, z3);
            } catch (Exception e3) {
                l("InternalListener exception in onRequestStart", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public boolean c(String str) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            if (((e) this.f2154a.get(i3)).c(str)) {
                return true;
            }
        }
        return false;
    }

    @Override // P0.e
    public void d(T0.b bVar, String str, boolean z3) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).d(bVar, str, z3);
            } catch (Exception e3) {
                l("InternalListener exception in onRequestSuccess", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void e(String str, String str2, String str3) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).e(str, str2, str3);
            } catch (Exception e3) {
                l("InternalListener exception in onIntermediateChunkStart", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void f(String str, String str2, Map map) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).f(str, str2, map);
            } catch (Exception e3) {
                l("InternalListener exception in onProducerFinishWithSuccess", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void g(String str, String str2) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).g(str, str2);
            } catch (Exception e3) {
                l("InternalListener exception in onProducerStart", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void h(String str, String str2, Throwable th, Map map) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).h(str, str2, th, map);
            } catch (Exception e3) {
                l("InternalListener exception in onProducerFinishWithFailure", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void i(String str, String str2, Map map) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).i(str, str2, map);
            } catch (Exception e3) {
                l("InternalListener exception in onProducerFinishWithCancellation", e3);
            }
        }
    }

    @Override // P0.e
    public void j(String str) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).j(str);
            } catch (Exception e3) {
                l("InternalListener exception in onRequestCancellation", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void k(String str, String str2, boolean z3) {
        int size = this.f2154a.size();
        for (int i3 = 0; i3 < size; i3++) {
            try {
                ((e) this.f2154a.get(i3)).k(str, str2, z3);
            } catch (Exception e3) {
                l("InternalListener exception in onProducerFinishWithSuccess", e3);
            }
        }
    }

    public c(e... eVarArr) {
        this.f2154a = new ArrayList(eVarArr.length);
        for (e eVar : eVarArr) {
            if (eVar != null) {
                this.f2154a.add(eVar);
            }
        }
    }
}
