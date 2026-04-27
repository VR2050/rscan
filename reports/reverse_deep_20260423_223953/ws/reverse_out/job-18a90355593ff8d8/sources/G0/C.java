package G0;

import b0.AbstractC0311a;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class C {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Class f765b = C.class;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Map f766a = new HashMap();

    private C() {
    }

    public static C d() {
        return new C();
    }

    private synchronized void e() {
        Y.a.y(f765b, "Count = %d", Integer.valueOf(this.f766a.size()));
    }

    public void a() {
        ArrayList arrayList;
        synchronized (this) {
            arrayList = new ArrayList(this.f766a.values());
            this.f766a.clear();
        }
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            N0.j jVar = (N0.j) arrayList.get(i3);
            if (jVar != null) {
                jVar.close();
            }
        }
    }

    public synchronized boolean b(R.d dVar) {
        X.k.g(dVar);
        if (!this.f766a.containsKey(dVar)) {
            return false;
        }
        N0.j jVar = (N0.j) this.f766a.get(dVar);
        synchronized (jVar) {
            if (N0.j.w0(jVar)) {
                return true;
            }
            this.f766a.remove(dVar);
            Y.a.G(f765b, "Found closed reference %d for key %s (%d)", Integer.valueOf(System.identityHashCode(jVar)), dVar.c(), Integer.valueOf(System.identityHashCode(dVar)));
            return false;
        }
    }

    public synchronized N0.j c(R.d dVar) {
        X.k.g(dVar);
        N0.j jVarI = (N0.j) this.f766a.get(dVar);
        if (jVarI != null) {
            synchronized (jVarI) {
                if (!N0.j.w0(jVarI)) {
                    this.f766a.remove(dVar);
                    Y.a.G(f765b, "Found closed reference %d for key %s (%d)", Integer.valueOf(System.identityHashCode(jVarI)), dVar.c(), Integer.valueOf(System.identityHashCode(dVar)));
                    return null;
                }
                jVarI = N0.j.i(jVarI);
            }
        }
        return jVarI;
    }

    public synchronized void f(R.d dVar, N0.j jVar) {
        X.k.g(dVar);
        X.k.b(Boolean.valueOf(N0.j.w0(jVar)));
        N0.j.p((N0.j) this.f766a.put(dVar, N0.j.i(jVar)));
        e();
    }

    public boolean g(R.d dVar) {
        N0.j jVar;
        X.k.g(dVar);
        synchronized (this) {
            jVar = (N0.j) this.f766a.remove(dVar);
        }
        if (jVar == null) {
            return false;
        }
        try {
            return jVar.v0();
        } finally {
            jVar.close();
        }
    }

    public synchronized boolean h(R.d dVar, N0.j jVar) {
        X.k.g(dVar);
        X.k.g(jVar);
        X.k.b(Boolean.valueOf(N0.j.w0(jVar)));
        N0.j jVar2 = (N0.j) this.f766a.get(dVar);
        if (jVar2 == null) {
            return false;
        }
        AbstractC0311a abstractC0311aV = jVar2.v();
        AbstractC0311a abstractC0311aV2 = jVar.v();
        if (abstractC0311aV != null && abstractC0311aV2 != null) {
            try {
                if (abstractC0311aV.P() == abstractC0311aV2.P()) {
                    this.f766a.remove(dVar);
                    AbstractC0311a.D(abstractC0311aV2);
                    AbstractC0311a.D(abstractC0311aV);
                    N0.j.p(jVar2);
                    e();
                    return true;
                }
            } finally {
                AbstractC0311a.D(abstractC0311aV2);
                AbstractC0311a.D(abstractC0311aV);
                N0.j.p(jVar2);
            }
        }
        return false;
    }
}
