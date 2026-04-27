package androidx.lifecycle;

import androidx.lifecycle.f;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import k.C0602a;
import k.b;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class l extends f {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final a f5143j = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f5144b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private C0602a f5145c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private f.b f5146d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final WeakReference f5147e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f5148f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f5149g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f5150h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private ArrayList f5151i;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final f.b a(f.b bVar, f.b bVar2) {
            t2.j.f(bVar, "state1");
            return (bVar2 == null || bVar2.compareTo(bVar) >= 0) ? bVar : bVar2;
        }

        private a() {
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private f.b f5152a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private i f5153b;

        public b(j jVar, f.b bVar) {
            t2.j.f(bVar, "initialState");
            t2.j.c(jVar);
            this.f5153b = m.f(jVar);
            this.f5152a = bVar;
        }

        public final void a(k kVar, f.a aVar) {
            t2.j.f(aVar, "event");
            f.b bVarB = aVar.b();
            this.f5152a = l.f5143j.a(this.f5152a, bVarB);
            i iVar = this.f5153b;
            t2.j.c(kVar);
            iVar.d(kVar, aVar);
            this.f5152a = bVarB;
        }

        public final f.b b() {
            return this.f5152a;
        }
    }

    private l(k kVar, boolean z3) {
        this.f5144b = z3;
        this.f5145c = new C0602a();
        this.f5146d = f.b.INITIALIZED;
        this.f5151i = new ArrayList();
        this.f5147e = new WeakReference(kVar);
    }

    private final void d(k kVar) {
        Iterator itA = this.f5145c.a();
        t2.j.e(itA, "observerMap.descendingIterator()");
        while (itA.hasNext() && !this.f5150h) {
            Map.Entry entry = (Map.Entry) itA.next();
            t2.j.e(entry, "next()");
            j jVar = (j) entry.getKey();
            b bVar = (b) entry.getValue();
            while (bVar.b().compareTo(this.f5146d) > 0 && !this.f5150h && this.f5145c.contains(jVar)) {
                f.a aVarA = f.a.Companion.a(bVar.b());
                if (aVarA == null) {
                    throw new IllegalStateException("no event down from " + bVar.b());
                }
                l(aVarA.b());
                bVar.a(kVar, aVarA);
                k();
            }
        }
    }

    private final f.b e(j jVar) {
        b bVar;
        Map.Entry entryK = this.f5145c.k(jVar);
        f.b bVar2 = null;
        f.b bVarB = (entryK == null || (bVar = (b) entryK.getValue()) == null) ? null : bVar.b();
        if (!this.f5151i.isEmpty()) {
            bVar2 = (f.b) this.f5151i.get(r0.size() - 1);
        }
        a aVar = f5143j;
        return aVar.a(aVar.a(this.f5146d, bVarB), bVar2);
    }

    private final void f(String str) {
        if (!this.f5144b || j.c.f().b()) {
            return;
        }
        throw new IllegalStateException(("Method " + str + " must be called on the main thread").toString());
    }

    private final void g(k kVar) {
        b.d dVarE = this.f5145c.e();
        t2.j.e(dVarE, "observerMap.iteratorWithAdditions()");
        while (dVarE.hasNext() && !this.f5150h) {
            Map.Entry entry = (Map.Entry) dVarE.next();
            j jVar = (j) entry.getKey();
            b bVar = (b) entry.getValue();
            while (bVar.b().compareTo(this.f5146d) < 0 && !this.f5150h && this.f5145c.contains(jVar)) {
                l(bVar.b());
                f.a aVarB = f.a.Companion.b(bVar.b());
                if (aVarB == null) {
                    throw new IllegalStateException("no event up from " + bVar.b());
                }
                bVar.a(kVar, aVarB);
                k();
            }
        }
    }

    private final boolean i() {
        if (this.f5145c.size() == 0) {
            return true;
        }
        Map.Entry entryB = this.f5145c.b();
        t2.j.c(entryB);
        f.b bVarB = ((b) entryB.getValue()).b();
        Map.Entry entryF = this.f5145c.f();
        t2.j.c(entryF);
        f.b bVarB2 = ((b) entryF.getValue()).b();
        return bVarB == bVarB2 && this.f5146d == bVarB2;
    }

    private final void j(f.b bVar) {
        f.b bVar2 = this.f5146d;
        if (bVar2 == bVar) {
            return;
        }
        if (bVar2 == f.b.INITIALIZED && bVar == f.b.DESTROYED) {
            throw new IllegalStateException(("no event down from " + this.f5146d + " in component " + this.f5147e.get()).toString());
        }
        this.f5146d = bVar;
        if (this.f5149g || this.f5148f != 0) {
            this.f5150h = true;
            return;
        }
        this.f5149g = true;
        n();
        this.f5149g = false;
        if (this.f5146d == f.b.DESTROYED) {
            this.f5145c = new C0602a();
        }
    }

    private final void k() {
        this.f5151i.remove(r0.size() - 1);
    }

    private final void l(f.b bVar) {
        this.f5151i.add(bVar);
    }

    private final void n() {
        k kVar = (k) this.f5147e.get();
        if (kVar == null) {
            throw new IllegalStateException("LifecycleOwner of this LifecycleRegistry is already garbage collected. It is too late to change lifecycle state.");
        }
        while (!i()) {
            this.f5150h = false;
            f.b bVar = this.f5146d;
            Map.Entry entryB = this.f5145c.b();
            t2.j.c(entryB);
            if (bVar.compareTo(((b) entryB.getValue()).b()) < 0) {
                d(kVar);
            }
            Map.Entry entryF = this.f5145c.f();
            if (!this.f5150h && entryF != null && this.f5146d.compareTo(((b) entryF.getValue()).b()) > 0) {
                g(kVar);
            }
        }
        this.f5150h = false;
    }

    @Override // androidx.lifecycle.f
    public void a(j jVar) {
        k kVar;
        t2.j.f(jVar, "observer");
        f("addObserver");
        f.b bVar = this.f5146d;
        f.b bVar2 = f.b.DESTROYED;
        if (bVar != bVar2) {
            bVar2 = f.b.INITIALIZED;
        }
        b bVar3 = new b(jVar, bVar2);
        if (((b) this.f5145c.i(jVar, bVar3)) == null && (kVar = (k) this.f5147e.get()) != null) {
            boolean z3 = this.f5148f != 0 || this.f5149g;
            f.b bVarE = e(jVar);
            this.f5148f++;
            while (bVar3.b().compareTo(bVarE) < 0 && this.f5145c.contains(jVar)) {
                l(bVar3.b());
                f.a aVarB = f.a.Companion.b(bVar3.b());
                if (aVarB == null) {
                    throw new IllegalStateException("no event up from " + bVar3.b());
                }
                bVar3.a(kVar, aVarB);
                k();
                bVarE = e(jVar);
            }
            if (!z3) {
                n();
            }
            this.f5148f--;
        }
    }

    @Override // androidx.lifecycle.f
    public f.b b() {
        return this.f5146d;
    }

    @Override // androidx.lifecycle.f
    public void c(j jVar) {
        t2.j.f(jVar, "observer");
        f("removeObserver");
        this.f5145c.j(jVar);
    }

    public void h(f.a aVar) {
        t2.j.f(aVar, "event");
        f("handleLifecycleEvent");
        j(aVar.b());
    }

    public void m(f.b bVar) {
        t2.j.f(bVar, "state");
        f("setCurrentState");
        j(bVar);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public l(k kVar) {
        this(kVar, true);
        t2.j.f(kVar, "provider");
    }
}
