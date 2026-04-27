package androidx.fragment.app;

import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.os.b;
import androidx.core.view.V;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
abstract class L {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ViewGroup f4868a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final ArrayList f4869b = new ArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final ArrayList f4870c = new ArrayList();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    boolean f4871d = false;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    boolean f4872e = false;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ d f4873b;

        a(d dVar) {
            this.f4873b = dVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (L.this.f4869b.contains(this.f4873b)) {
                this.f4873b.e().a(this.f4873b.f().f4764J);
            }
        }
    }

    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ d f4875b;

        b(d dVar) {
            this.f4875b = dVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            L.this.f4869b.remove(this.f4875b);
            L.this.f4870c.remove(this.f4875b);
        }
    }

    static /* synthetic */ class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f4877a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        static final /* synthetic */ int[] f4878b;

        static {
            int[] iArr = new int[e.b.values().length];
            f4878b = iArr;
            try {
                iArr[e.b.ADDING.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f4878b[e.b.REMOVING.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f4878b[e.b.NONE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            int[] iArr2 = new int[e.c.values().length];
            f4877a = iArr2;
            try {
                iArr2[e.c.REMOVED.ordinal()] = 1;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f4877a[e.c.VISIBLE.ordinal()] = 2;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f4877a[e.c.GONE.ordinal()] = 3;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f4877a[e.c.INVISIBLE.ordinal()] = 4;
            } catch (NoSuchFieldError unused7) {
            }
        }
    }

    private static class d extends e {

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final D f4879h;

        d(e.c cVar, e.b bVar, D d3, androidx.core.os.b bVar2) {
            super(cVar, bVar, d3.k(), bVar2);
            this.f4879h = d3;
        }

        @Override // androidx.fragment.app.L.e
        public void c() {
            super.c();
            this.f4879h.m();
        }

        @Override // androidx.fragment.app.L.e
        void l() {
            if (g() != e.b.ADDING) {
                if (g() == e.b.REMOVING) {
                    Fragment fragmentK = this.f4879h.k();
                    View viewM1 = fragmentK.m1();
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "Clearing focus " + viewM1.findFocus() + " on view " + viewM1 + " for Fragment " + fragmentK);
                    }
                    viewM1.clearFocus();
                    return;
                }
                return;
            }
            Fragment fragmentK2 = this.f4879h.k();
            View viewFindFocus = fragmentK2.f4764J.findFocus();
            if (viewFindFocus != null) {
                fragmentK2.s1(viewFindFocus);
                if (x.G0(2)) {
                    Log.v("FragmentManager", "requestFocus: Saved focused view " + viewFindFocus + " for Fragment " + fragmentK2);
                }
            }
            View viewM12 = f().m1();
            if (viewM12.getParent() == null) {
                this.f4879h.b();
                viewM12.setAlpha(0.0f);
            }
            if (viewM12.getAlpha() == 0.0f && viewM12.getVisibility() == 0) {
                viewM12.setVisibility(4);
            }
            viewM12.setAlpha(fragmentK2.H());
        }
    }

    static class e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private c f4880a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private b f4881b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Fragment f4882c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final List f4883d = new ArrayList();

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final HashSet f4884e = new HashSet();

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f4885f = false;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private boolean f4886g = false;

        class a implements b.a {
            a() {
            }

            @Override // androidx.core.os.b.a
            public void a() {
                e.this.b();
            }
        }

        enum b {
            NONE,
            ADDING,
            REMOVING
        }

        enum c {
            REMOVED,
            VISIBLE,
            GONE,
            INVISIBLE;

            static c b(int i3) {
                if (i3 == 0) {
                    return VISIBLE;
                }
                if (i3 == 4) {
                    return INVISIBLE;
                }
                if (i3 == 8) {
                    return GONE;
                }
                throw new IllegalArgumentException("Unknown visibility " + i3);
            }

            static c c(View view) {
                return (view.getAlpha() == 0.0f && view.getVisibility() == 0) ? INVISIBLE : b(view.getVisibility());
            }

            void a(View view) {
                int i3 = c.f4877a[ordinal()];
                if (i3 == 1) {
                    ViewGroup viewGroup = (ViewGroup) view.getParent();
                    if (viewGroup != null) {
                        if (x.G0(2)) {
                            Log.v("FragmentManager", "SpecialEffectsController: Removing view " + view + " from container " + viewGroup);
                        }
                        viewGroup.removeView(view);
                        return;
                    }
                    return;
                }
                if (i3 == 2) {
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "SpecialEffectsController: Setting view " + view + " to VISIBLE");
                    }
                    view.setVisibility(0);
                    return;
                }
                if (i3 == 3) {
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "SpecialEffectsController: Setting view " + view + " to GONE");
                    }
                    view.setVisibility(8);
                    return;
                }
                if (i3 != 4) {
                    return;
                }
                if (x.G0(2)) {
                    Log.v("FragmentManager", "SpecialEffectsController: Setting view " + view + " to INVISIBLE");
                }
                view.setVisibility(4);
            }
        }

        e(c cVar, b bVar, Fragment fragment, androidx.core.os.b bVar2) {
            this.f4880a = cVar;
            this.f4881b = bVar;
            this.f4882c = fragment;
            bVar2.b(new a());
        }

        final void a(Runnable runnable) {
            this.f4883d.add(runnable);
        }

        final void b() {
            if (h()) {
                return;
            }
            this.f4885f = true;
            if (this.f4884e.isEmpty()) {
                c();
                return;
            }
            Iterator it = new ArrayList(this.f4884e).iterator();
            while (it.hasNext()) {
                ((androidx.core.os.b) it.next()).a();
            }
        }

        public void c() {
            if (this.f4886g) {
                return;
            }
            if (x.G0(2)) {
                Log.v("FragmentManager", "SpecialEffectsController: " + this + " has called complete.");
            }
            this.f4886g = true;
            Iterator it = this.f4883d.iterator();
            while (it.hasNext()) {
                ((Runnable) it.next()).run();
            }
        }

        public final void d(androidx.core.os.b bVar) {
            if (this.f4884e.remove(bVar) && this.f4884e.isEmpty()) {
                c();
            }
        }

        public c e() {
            return this.f4880a;
        }

        public final Fragment f() {
            return this.f4882c;
        }

        b g() {
            return this.f4881b;
        }

        final boolean h() {
            return this.f4885f;
        }

        final boolean i() {
            return this.f4886g;
        }

        public final void j(androidx.core.os.b bVar) {
            l();
            this.f4884e.add(bVar);
        }

        final void k(c cVar, b bVar) {
            int i3 = c.f4878b[bVar.ordinal()];
            if (i3 == 1) {
                if (this.f4880a == c.REMOVED) {
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "SpecialEffectsController: For fragment " + this.f4882c + " mFinalState = REMOVED -> VISIBLE. mLifecycleImpact = " + this.f4881b + " to ADDING.");
                    }
                    this.f4880a = c.VISIBLE;
                    this.f4881b = b.ADDING;
                    return;
                }
                return;
            }
            if (i3 == 2) {
                if (x.G0(2)) {
                    Log.v("FragmentManager", "SpecialEffectsController: For fragment " + this.f4882c + " mFinalState = " + this.f4880a + " -> REMOVED. mLifecycleImpact  = " + this.f4881b + " to REMOVING.");
                }
                this.f4880a = c.REMOVED;
                this.f4881b = b.REMOVING;
                return;
            }
            if (i3 == 3 && this.f4880a != c.REMOVED) {
                if (x.G0(2)) {
                    Log.v("FragmentManager", "SpecialEffectsController: For fragment " + this.f4882c + " mFinalState = " + this.f4880a + " -> " + cVar + ". ");
                }
                this.f4880a = cVar;
            }
        }

        abstract void l();

        public String toString() {
            return "Operation {" + Integer.toHexString(System.identityHashCode(this)) + "} {mFinalState = " + this.f4880a + "} {mLifecycleImpact = " + this.f4881b + "} {mFragment = " + this.f4882c + "}";
        }
    }

    L(ViewGroup viewGroup) {
        this.f4868a = viewGroup;
    }

    private void a(e.c cVar, e.b bVar, D d3) {
        synchronized (this.f4869b) {
            try {
                androidx.core.os.b bVar2 = new androidx.core.os.b();
                e eVarH = h(d3.k());
                if (eVarH != null) {
                    eVarH.k(cVar, bVar);
                    return;
                }
                d dVar = new d(cVar, bVar, d3, bVar2);
                this.f4869b.add(dVar);
                dVar.a(new a(dVar));
                dVar.a(new b(dVar));
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private e h(Fragment fragment) {
        for (e eVar : this.f4869b) {
            if (eVar.f().equals(fragment) && !eVar.h()) {
                return eVar;
            }
        }
        return null;
    }

    private e i(Fragment fragment) {
        for (e eVar : this.f4870c) {
            if (eVar.f().equals(fragment) && !eVar.h()) {
                return eVar;
            }
        }
        return null;
    }

    static L n(ViewGroup viewGroup, x xVar) {
        return o(viewGroup, xVar.y0());
    }

    static L o(ViewGroup viewGroup, M m3) {
        Object tag = viewGroup.getTag(A.b.f7b);
        if (tag instanceof L) {
            return (L) tag;
        }
        L lA = m3.a(viewGroup);
        viewGroup.setTag(A.b.f7b, lA);
        return lA;
    }

    private void q() {
        for (e eVar : this.f4869b) {
            if (eVar.g() == e.b.ADDING) {
                eVar.k(e.c.b(eVar.f().m1().getVisibility()), e.b.NONE);
            }
        }
    }

    void b(e.c cVar, D d3) {
        if (x.G0(2)) {
            Log.v("FragmentManager", "SpecialEffectsController: Enqueuing add operation for fragment " + d3.k());
        }
        a(cVar, e.b.ADDING, d3);
    }

    void c(D d3) {
        if (x.G0(2)) {
            Log.v("FragmentManager", "SpecialEffectsController: Enqueuing hide operation for fragment " + d3.k());
        }
        a(e.c.GONE, e.b.NONE, d3);
    }

    void d(D d3) {
        if (x.G0(2)) {
            Log.v("FragmentManager", "SpecialEffectsController: Enqueuing remove operation for fragment " + d3.k());
        }
        a(e.c.REMOVED, e.b.REMOVING, d3);
    }

    void e(D d3) {
        if (x.G0(2)) {
            Log.v("FragmentManager", "SpecialEffectsController: Enqueuing show operation for fragment " + d3.k());
        }
        a(e.c.VISIBLE, e.b.NONE, d3);
    }

    abstract void f(List list, boolean z3);

    void g() {
        if (this.f4872e) {
            return;
        }
        if (!V.E(this.f4868a)) {
            j();
            this.f4871d = false;
            return;
        }
        synchronized (this.f4869b) {
            try {
                if (!this.f4869b.isEmpty()) {
                    ArrayList<e> arrayList = new ArrayList(this.f4870c);
                    this.f4870c.clear();
                    for (e eVar : arrayList) {
                        if (x.G0(2)) {
                            Log.v("FragmentManager", "SpecialEffectsController: Cancelling operation " + eVar);
                        }
                        eVar.b();
                        if (!eVar.i()) {
                            this.f4870c.add(eVar);
                        }
                    }
                    q();
                    ArrayList arrayList2 = new ArrayList(this.f4869b);
                    this.f4869b.clear();
                    this.f4870c.addAll(arrayList2);
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "SpecialEffectsController: Executing pending operations");
                    }
                    Iterator it = arrayList2.iterator();
                    while (it.hasNext()) {
                        ((e) it.next()).l();
                    }
                    f(arrayList2, this.f4871d);
                    this.f4871d = false;
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "SpecialEffectsController: Finished executing pending operations");
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    void j() {
        if (x.G0(2)) {
            Log.v("FragmentManager", "SpecialEffectsController: Forcing all operations to complete");
        }
        boolean zE = V.E(this.f4868a);
        synchronized (this.f4869b) {
            try {
                q();
                Iterator it = this.f4869b.iterator();
                while (it.hasNext()) {
                    ((e) it.next()).l();
                }
                for (e eVar : new ArrayList(this.f4870c)) {
                    if (x.G0(2)) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("SpecialEffectsController: ");
                        sb.append(zE ? "" : "Container " + this.f4868a + " is not attached to window. ");
                        sb.append("Cancelling running operation ");
                        sb.append(eVar);
                        Log.v("FragmentManager", sb.toString());
                    }
                    eVar.b();
                }
                for (e eVar2 : new ArrayList(this.f4869b)) {
                    if (x.G0(2)) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("SpecialEffectsController: ");
                        sb2.append(zE ? "" : "Container " + this.f4868a + " is not attached to window. ");
                        sb2.append("Cancelling pending operation ");
                        sb2.append(eVar2);
                        Log.v("FragmentManager", sb2.toString());
                    }
                    eVar2.b();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    void k() {
        if (this.f4872e) {
            if (x.G0(2)) {
                Log.v("FragmentManager", "SpecialEffectsController: Forcing postponed operations");
            }
            this.f4872e = false;
            g();
        }
    }

    e.b l(D d3) {
        e eVarH = h(d3.k());
        e.b bVarG = eVarH != null ? eVarH.g() : null;
        e eVarI = i(d3.k());
        return (eVarI == null || !(bVarG == null || bVarG == e.b.NONE)) ? bVarG : eVarI.g();
    }

    public ViewGroup m() {
        return this.f4868a;
    }

    void p() {
        synchronized (this.f4869b) {
            try {
                q();
                this.f4872e = false;
                int size = this.f4869b.size() - 1;
                while (true) {
                    if (size < 0) {
                        break;
                    }
                    e eVar = (e) this.f4869b.get(size);
                    e.c cVarC = e.c.c(eVar.f().f4764J);
                    e.c cVarE = eVar.e();
                    e.c cVar = e.c.VISIBLE;
                    if (cVarE == cVar && cVarC != cVar) {
                        this.f4872e = eVar.f().Z();
                        break;
                    }
                    size--;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    void r(boolean z3) {
        this.f4871d = z3;
    }
}
