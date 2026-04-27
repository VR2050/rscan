package P0;

import com.facebook.imagepipeline.producers.e0;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b implements d {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2152b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f2153a;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public b(Set set) {
        if (set == null) {
            this.f2153a = new ArrayList();
            return;
        }
        ArrayList arrayList = new ArrayList(set.size());
        this.f2153a = arrayList;
        AbstractC0586n.C(set, arrayList);
    }

    @Override // P0.d
    public void a(e0 e0Var) {
        j.f(e0Var, "producerContext");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).a(e0Var);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onRequestCancellation", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void b(e0 e0Var, String str, String str2) {
        j.f(e0Var, "producerContext");
        j.f(str, "producerName");
        j.f(str2, "producerEventName");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).b(e0Var, str, str2);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onIntermediateChunkStart", e3);
            }
        }
    }

    @Override // P0.d
    public void c(e0 e0Var) {
        j.f(e0Var, "producerContext");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).c(e0Var);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onRequestStart", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void d(e0 e0Var, String str, Map map) {
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).d(e0Var, str, map);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onProducerFinishWithSuccess", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void e(e0 e0Var, String str, boolean z3) {
        j.f(e0Var, "producerContext");
        j.f(str, "producerName");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).e(e0Var, str, z3);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onProducerFinishWithSuccess", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void f(e0 e0Var, String str, Map map) {
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).f(e0Var, str, map);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onProducerFinishWithCancellation", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void g(e0 e0Var, String str) {
        j.f(e0Var, "producerContext");
        j.f(str, "producerName");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).g(e0Var, str);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onProducerStart", e3);
            }
        }
    }

    @Override // P0.d
    public void h(e0 e0Var) {
        j.f(e0Var, "producerContext");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).h(e0Var);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onRequestSuccess", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void i(e0 e0Var, String str, Throwable th, Map map) {
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).i(e0Var, str, th, map);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onProducerFinishWithFailure", e3);
            }
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public boolean j(e0 e0Var, String str) {
        j.f(e0Var, "producerContext");
        j.f(str, "producerName");
        List list = this.f2153a;
        if (list != null && list.isEmpty()) {
            return false;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            if (((d) it.next()).j(e0Var, str)) {
                return true;
            }
        }
        return false;
    }

    @Override // P0.d
    public void k(e0 e0Var, Throwable th) {
        j.f(e0Var, "producerContext");
        j.f(th, "throwable");
        Iterator it = this.f2153a.iterator();
        while (it.hasNext()) {
            try {
                ((d) it.next()).k(e0Var, th);
            } catch (Exception e3) {
                Y.a.n("ForwardingRequestListener2", "InternalListener exception in onRequestFailure", e3);
            }
        }
    }
}
