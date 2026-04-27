package androidx.fragment.app;

import android.animation.Animator;
import android.app.Activity;
import android.app.Application;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Looper;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import androidx.core.view.AbstractC0283u;
import androidx.lifecycle.InterfaceC0307e;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.f;
import androidx.lifecycle.z;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes.dex */
public abstract class Fragment implements ComponentCallbacks, View.OnCreateContextMenuListener, androidx.lifecycle.k, androidx.lifecycle.C, InterfaceC0307e, F.d {

    /* JADX INFO: renamed from: c0, reason: collision with root package name */
    static final Object f4754c0 = new Object();

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    String f4755A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    boolean f4756B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    boolean f4757C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    boolean f4758D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    boolean f4759E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    boolean f4760F;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private boolean f4762H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    ViewGroup f4763I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    View f4764J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    boolean f4765K;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    f f4767M;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    boolean f4769O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    LayoutInflater f4770P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    boolean f4771Q;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    public String f4772R;

    /* JADX INFO: renamed from: T, reason: collision with root package name */
    androidx.lifecycle.l f4774T;

    /* JADX INFO: renamed from: U, reason: collision with root package name */
    J f4775U;

    /* JADX INFO: renamed from: W, reason: collision with root package name */
    z.b f4777W;

    /* JADX INFO: renamed from: X, reason: collision with root package name */
    F.c f4778X;

    /* JADX INFO: renamed from: Y, reason: collision with root package name */
    private int f4779Y;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    Bundle f4784c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    SparseArray f4785d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    Bundle f4786e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    Boolean f4787f;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    Bundle f4789h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    Fragment f4790i;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    int f4792k;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    boolean f4794m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    boolean f4795n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    boolean f4796o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    boolean f4797p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    boolean f4798q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    boolean f4799r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    boolean f4800s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    int f4801t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    x f4802u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    p f4803v;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    Fragment f4805x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    int f4806y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    int f4807z;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    int f4782b = -1;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    String f4788g = UUID.randomUUID().toString();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    String f4791j = null;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Boolean f4793l = null;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    x f4804w = new y();

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    boolean f4761G = true;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    boolean f4766L = true;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    Runnable f4768N = new a();

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    f.b f4773S = f.b.RESUMED;

    /* JADX INFO: renamed from: V, reason: collision with root package name */
    androidx.lifecycle.o f4776V = new androidx.lifecycle.o();

    /* JADX INFO: renamed from: Z, reason: collision with root package name */
    private final AtomicInteger f4780Z = new AtomicInteger();

    /* JADX INFO: renamed from: a0, reason: collision with root package name */
    private final ArrayList f4781a0 = new ArrayList();

    /* JADX INFO: renamed from: b0, reason: collision with root package name */
    private final i f4783b0 = new b();

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Fragment.this.x1();
        }
    }

    class b extends i {
        b() {
            super(null);
        }

        @Override // androidx.fragment.app.Fragment.i
        void a() {
            Fragment.this.f4778X.c();
            androidx.lifecycle.v.a(Fragment.this);
        }
    }

    class c implements Runnable {
        c() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Fragment.this.c(false);
        }
    }

    class d implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ L f4812b;

        d(L l3) {
            this.f4812b = l3;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f4812b.g();
        }
    }

    class e extends AbstractC0300l {
        e() {
        }

        @Override // androidx.fragment.app.AbstractC0300l
        public View f(int i3) {
            View view = Fragment.this.f4764J;
            if (view != null) {
                return view.findViewById(i3);
            }
            throw new IllegalStateException("Fragment " + Fragment.this + " does not have a view");
        }

        @Override // androidx.fragment.app.AbstractC0300l
        public boolean h() {
            return Fragment.this.f4764J != null;
        }
    }

    static class f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        View f4815a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        boolean f4816b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        int f4817c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        int f4818d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        int f4819e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        int f4820f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        int f4821g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        ArrayList f4822h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        ArrayList f4823i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        Object f4824j = null;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        Object f4825k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        Object f4826l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        Object f4827m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        Object f4828n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        Object f4829o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        Boolean f4830p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        Boolean f4831q;

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        float f4832r;

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        View f4833s;

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        boolean f4834t;

        f() {
            Object obj = Fragment.f4754c0;
            this.f4825k = obj;
            this.f4826l = null;
            this.f4827m = obj;
            this.f4828n = null;
            this.f4829o = obj;
            this.f4832r = 1.0f;
            this.f4833s = null;
        }
    }

    static class g {
        static void a(View view) {
            view.cancelPendingInputEvents();
        }
    }

    public static class h extends RuntimeException {
        public h(String str, Exception exc) {
            super(str, exc);
        }
    }

    private static abstract class i {
        private i() {
        }

        abstract void a();

        /* synthetic */ i(a aVar) {
            this();
        }
    }

    public Fragment() {
        S();
    }

    private int A() {
        f.b bVar = this.f4773S;
        return (bVar == f.b.INITIALIZED || this.f4805x == null) ? bVar.ordinal() : Math.min(bVar.ordinal(), this.f4805x.A());
    }

    private Fragment P(boolean z3) {
        String str;
        if (z3) {
            B.c.h(this);
        }
        Fragment fragment = this.f4790i;
        if (fragment != null) {
            return fragment;
        }
        x xVar = this.f4802u;
        if (xVar == null || (str = this.f4791j) == null) {
            return null;
        }
        return xVar.e0(str);
    }

    private void S() {
        this.f4774T = new androidx.lifecycle.l(this);
        this.f4778X = F.c.a(this);
        this.f4777W = null;
        if (this.f4781a0.contains(this.f4783b0)) {
            return;
        }
        i1(this.f4783b0);
    }

    public static Fragment U(Context context, String str, Bundle bundle) {
        try {
            Fragment fragment = (Fragment) o.d(context.getClassLoader(), str).getConstructor(new Class[0]).newInstance(new Object[0]);
            if (bundle != null) {
                bundle.setClassLoader(fragment.getClass().getClassLoader());
                fragment.r1(bundle);
            }
            return fragment;
        } catch (IllegalAccessException e3) {
            throw new h("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an empty constructor that is public", e3);
        } catch (InstantiationException e4) {
            throw new h("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an empty constructor that is public", e4);
        } catch (NoSuchMethodException e5) {
            throw new h("Unable to instantiate fragment " + str + ": could not find Fragment constructor", e5);
        } catch (InvocationTargetException e6) {
            throw new h("Unable to instantiate fragment " + str + ": calling Fragment constructor caused an exception", e6);
        }
    }

    private f f() {
        if (this.f4767M == null) {
            this.f4767M = new f();
        }
        return this.f4767M;
    }

    private void i1(i iVar) {
        if (this.f4782b >= 0) {
            iVar.a();
        } else {
            this.f4781a0.add(iVar);
        }
    }

    private void o1() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto RESTORE_VIEW_STATE: " + this);
        }
        if (this.f4764J != null) {
            p1(this.f4784c);
        }
        this.f4784c = null;
    }

    public void A0(boolean z3) {
    }

    int B() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return 0;
        }
        return fVar.f4821g;
    }

    public void B0(Menu menu) {
    }

    public final Fragment C() {
        return this.f4805x;
    }

    public void C0(boolean z3) {
    }

    public final x D() {
        x xVar = this.f4802u;
        if (xVar != null) {
            return xVar;
        }
        throw new IllegalStateException("Fragment " + this + " not associated with a fragment manager.");
    }

    public void D0(int i3, String[] strArr, int[] iArr) {
    }

    boolean E() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return false;
        }
        return fVar.f4816b;
    }

    public void E0() {
        this.f4762H = true;
    }

    int F() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return 0;
        }
        return fVar.f4819e;
    }

    public void F0(Bundle bundle) {
    }

    int G() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return 0;
        }
        return fVar.f4820f;
    }

    public void G0() {
        this.f4762H = true;
    }

    float H() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return 1.0f;
        }
        return fVar.f4832r;
    }

    public void H0() {
        this.f4762H = true;
    }

    public Object I() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        Object obj = fVar.f4827m;
        return obj == f4754c0 ? v() : obj;
    }

    public void I0(View view, Bundle bundle) {
    }

    public final Resources J() {
        return l1().getResources();
    }

    public void J0(Bundle bundle) {
        this.f4762H = true;
    }

    public Object K() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        Object obj = fVar.f4825k;
        return obj == f4754c0 ? q() : obj;
    }

    void K0(Bundle bundle) {
        this.f4804w.U0();
        this.f4782b = 3;
        this.f4762H = false;
        d0(bundle);
        if (this.f4762H) {
            o1();
            this.f4804w.x();
        } else {
            throw new N("Fragment " + this + " did not call through to super.onActivityCreated()");
        }
    }

    public Object L() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        return fVar.f4828n;
    }

    void L0() {
        Iterator it = this.f4781a0.iterator();
        while (it.hasNext()) {
            ((i) it.next()).a();
        }
        this.f4781a0.clear();
        this.f4804w.m(this.f4803v, d(), this);
        this.f4782b = 0;
        this.f4762H = false;
        g0(this.f4803v.k());
        if (this.f4762H) {
            this.f4802u.H(this);
            this.f4804w.y();
        } else {
            throw new N("Fragment " + this + " did not call through to super.onAttach()");
        }
    }

    public Object M() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        Object obj = fVar.f4829o;
        return obj == f4754c0 ? L() : obj;
    }

    void M0(Configuration configuration) {
        onConfigurationChanged(configuration);
    }

    ArrayList N() {
        ArrayList arrayList;
        f fVar = this.f4767M;
        return (fVar == null || (arrayList = fVar.f4822h) == null) ? new ArrayList() : arrayList;
    }

    boolean N0(MenuItem menuItem) {
        if (this.f4756B) {
            return false;
        }
        if (i0(menuItem)) {
            return true;
        }
        return this.f4804w.A(menuItem);
    }

    ArrayList O() {
        ArrayList arrayList;
        f fVar = this.f4767M;
        return (fVar == null || (arrayList = fVar.f4823i) == null) ? new ArrayList() : arrayList;
    }

    void O0(Bundle bundle) {
        this.f4804w.U0();
        this.f4782b = 1;
        this.f4762H = false;
        this.f4774T.a(new androidx.lifecycle.i() { // from class: androidx.fragment.app.Fragment.6
            @Override // androidx.lifecycle.i
            public void d(androidx.lifecycle.k kVar, f.a aVar) {
                View view;
                if (aVar != f.a.ON_STOP || (view = Fragment.this.f4764J) == null) {
                    return;
                }
                g.a(view);
            }
        });
        this.f4778X.d(bundle);
        j0(bundle);
        this.f4771Q = true;
        if (this.f4762H) {
            this.f4774T.h(f.a.ON_CREATE);
            return;
        }
        throw new N("Fragment " + this + " did not call through to super.onCreate()");
    }

    boolean P0(Menu menu, MenuInflater menuInflater) {
        boolean z3 = false;
        if (this.f4756B) {
            return false;
        }
        if (this.f4760F && this.f4761G) {
            m0(menu, menuInflater);
            z3 = true;
        }
        return z3 | this.f4804w.C(menu, menuInflater);
    }

    public View Q() {
        return this.f4764J;
    }

    void Q0(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        this.f4804w.U0();
        this.f4800s = true;
        this.f4775U = new J(this, r());
        View viewN0 = n0(layoutInflater, viewGroup, bundle);
        this.f4764J = viewN0;
        if (viewN0 == null) {
            if (this.f4775U.e()) {
                throw new IllegalStateException("Called getViewLifecycleOwner() but onCreateView() returned null");
            }
            this.f4775U = null;
        } else {
            this.f4775U.d();
            androidx.lifecycle.D.a(this.f4764J, this.f4775U);
            androidx.lifecycle.E.a(this.f4764J, this.f4775U);
            F.e.a(this.f4764J, this.f4775U);
            this.f4776V.i(this.f4775U);
        }
    }

    public LiveData R() {
        return this.f4776V;
    }

    void R0() {
        this.f4804w.D();
        this.f4774T.h(f.a.ON_DESTROY);
        this.f4782b = 0;
        this.f4762H = false;
        this.f4771Q = false;
        o0();
        if (this.f4762H) {
            return;
        }
        throw new N("Fragment " + this + " did not call through to super.onDestroy()");
    }

    void S0() {
        this.f4804w.E();
        if (this.f4764J != null && this.f4775U.s().b().b(f.b.CREATED)) {
            this.f4775U.c(f.a.ON_DESTROY);
        }
        this.f4782b = 1;
        this.f4762H = false;
        q0();
        if (this.f4762H) {
            androidx.loader.app.a.b(this).c();
            this.f4800s = false;
        } else {
            throw new N("Fragment " + this + " did not call through to super.onDestroyView()");
        }
    }

    void T() {
        S();
        this.f4772R = this.f4788g;
        this.f4788g = UUID.randomUUID().toString();
        this.f4794m = false;
        this.f4795n = false;
        this.f4797p = false;
        this.f4798q = false;
        this.f4799r = false;
        this.f4801t = 0;
        this.f4802u = null;
        this.f4804w = new y();
        this.f4803v = null;
        this.f4806y = 0;
        this.f4807z = 0;
        this.f4755A = null;
        this.f4756B = false;
        this.f4757C = false;
    }

    void T0() {
        this.f4782b = -1;
        this.f4762H = false;
        r0();
        this.f4770P = null;
        if (this.f4762H) {
            if (this.f4804w.F0()) {
                return;
            }
            this.f4804w.D();
            this.f4804w = new y();
            return;
        }
        throw new N("Fragment " + this + " did not call through to super.onDetach()");
    }

    LayoutInflater U0(Bundle bundle) {
        LayoutInflater layoutInflaterS0 = s0(bundle);
        this.f4770P = layoutInflaterS0;
        return layoutInflaterS0;
    }

    public final boolean V() {
        return this.f4803v != null && this.f4794m;
    }

    void V0() {
        onLowMemory();
    }

    public final boolean W() {
        x xVar;
        return this.f4756B || ((xVar = this.f4802u) != null && xVar.J0(this.f4805x));
    }

    void W0(boolean z3) {
        w0(z3);
    }

    final boolean X() {
        return this.f4801t > 0;
    }

    boolean X0(MenuItem menuItem) {
        if (this.f4756B) {
            return false;
        }
        if (this.f4760F && this.f4761G && x0(menuItem)) {
            return true;
        }
        return this.f4804w.J(menuItem);
    }

    public final boolean Y() {
        x xVar;
        return this.f4761G && ((xVar = this.f4802u) == null || xVar.K0(this.f4805x));
    }

    void Y0(Menu menu) {
        if (this.f4756B) {
            return;
        }
        if (this.f4760F && this.f4761G) {
            y0(menu);
        }
        this.f4804w.K(menu);
    }

    boolean Z() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return false;
        }
        return fVar.f4834t;
    }

    void Z0() {
        this.f4804w.M();
        if (this.f4764J != null) {
            this.f4775U.c(f.a.ON_PAUSE);
        }
        this.f4774T.h(f.a.ON_PAUSE);
        this.f4782b = 6;
        this.f4762H = false;
        z0();
        if (this.f4762H) {
            return;
        }
        throw new N("Fragment " + this + " did not call through to super.onPause()");
    }

    public final boolean a0() {
        return this.f4782b >= 7;
    }

    void a1(boolean z3) {
        A0(z3);
    }

    @Override // F.d
    public final androidx.savedstate.a b() {
        return this.f4778X.b();
    }

    public final boolean b0() {
        x xVar = this.f4802u;
        if (xVar == null) {
            return false;
        }
        return xVar.N0();
    }

    boolean b1(Menu menu) {
        boolean z3 = false;
        if (this.f4756B) {
            return false;
        }
        if (this.f4760F && this.f4761G) {
            B0(menu);
            z3 = true;
        }
        return z3 | this.f4804w.O(menu);
    }

    void c(boolean z3) {
        ViewGroup viewGroup;
        x xVar;
        f fVar = this.f4767M;
        if (fVar != null) {
            fVar.f4834t = false;
        }
        if (this.f4764J == null || (viewGroup = this.f4763I) == null || (xVar = this.f4802u) == null) {
            return;
        }
        L lN = L.n(viewGroup, xVar);
        lN.p();
        if (z3) {
            this.f4803v.o().post(new d(lN));
        } else {
            lN.g();
        }
    }

    void c0() {
        this.f4804w.U0();
    }

    void c1() {
        boolean zL0 = this.f4802u.L0(this);
        Boolean bool = this.f4793l;
        if (bool == null || bool.booleanValue() != zL0) {
            this.f4793l = Boolean.valueOf(zL0);
            C0(zL0);
            this.f4804w.P();
        }
    }

    AbstractC0300l d() {
        return new e();
    }

    public void d0(Bundle bundle) {
        this.f4762H = true;
    }

    void d1() {
        this.f4804w.U0();
        this.f4804w.a0(true);
        this.f4782b = 7;
        this.f4762H = false;
        E0();
        if (!this.f4762H) {
            throw new N("Fragment " + this + " did not call through to super.onResume()");
        }
        androidx.lifecycle.l lVar = this.f4774T;
        f.a aVar = f.a.ON_RESUME;
        lVar.h(aVar);
        if (this.f4764J != null) {
            this.f4775U.c(aVar);
        }
        this.f4804w.Q();
    }

    public void e(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mFragmentId=#");
        printWriter.print(Integer.toHexString(this.f4806y));
        printWriter.print(" mContainerId=#");
        printWriter.print(Integer.toHexString(this.f4807z));
        printWriter.print(" mTag=");
        printWriter.println(this.f4755A);
        printWriter.print(str);
        printWriter.print("mState=");
        printWriter.print(this.f4782b);
        printWriter.print(" mWho=");
        printWriter.print(this.f4788g);
        printWriter.print(" mBackStackNesting=");
        printWriter.println(this.f4801t);
        printWriter.print(str);
        printWriter.print("mAdded=");
        printWriter.print(this.f4794m);
        printWriter.print(" mRemoving=");
        printWriter.print(this.f4795n);
        printWriter.print(" mFromLayout=");
        printWriter.print(this.f4797p);
        printWriter.print(" mInLayout=");
        printWriter.println(this.f4798q);
        printWriter.print(str);
        printWriter.print("mHidden=");
        printWriter.print(this.f4756B);
        printWriter.print(" mDetached=");
        printWriter.print(this.f4757C);
        printWriter.print(" mMenuVisible=");
        printWriter.print(this.f4761G);
        printWriter.print(" mHasMenu=");
        printWriter.println(this.f4760F);
        printWriter.print(str);
        printWriter.print("mRetainInstance=");
        printWriter.print(this.f4758D);
        printWriter.print(" mUserVisibleHint=");
        printWriter.println(this.f4766L);
        if (this.f4802u != null) {
            printWriter.print(str);
            printWriter.print("mFragmentManager=");
            printWriter.println(this.f4802u);
        }
        if (this.f4803v != null) {
            printWriter.print(str);
            printWriter.print("mHost=");
            printWriter.println(this.f4803v);
        }
        if (this.f4805x != null) {
            printWriter.print(str);
            printWriter.print("mParentFragment=");
            printWriter.println(this.f4805x);
        }
        if (this.f4789h != null) {
            printWriter.print(str);
            printWriter.print("mArguments=");
            printWriter.println(this.f4789h);
        }
        if (this.f4784c != null) {
            printWriter.print(str);
            printWriter.print("mSavedFragmentState=");
            printWriter.println(this.f4784c);
        }
        if (this.f4785d != null) {
            printWriter.print(str);
            printWriter.print("mSavedViewState=");
            printWriter.println(this.f4785d);
        }
        if (this.f4786e != null) {
            printWriter.print(str);
            printWriter.print("mSavedViewRegistryState=");
            printWriter.println(this.f4786e);
        }
        Fragment fragmentP = P(false);
        if (fragmentP != null) {
            printWriter.print(str);
            printWriter.print("mTarget=");
            printWriter.print(fragmentP);
            printWriter.print(" mTargetRequestCode=");
            printWriter.println(this.f4792k);
        }
        printWriter.print(str);
        printWriter.print("mPopDirection=");
        printWriter.println(E());
        if (p() != 0) {
            printWriter.print(str);
            printWriter.print("getEnterAnim=");
            printWriter.println(p());
        }
        if (u() != 0) {
            printWriter.print(str);
            printWriter.print("getExitAnim=");
            printWriter.println(u());
        }
        if (F() != 0) {
            printWriter.print(str);
            printWriter.print("getPopEnterAnim=");
            printWriter.println(F());
        }
        if (G() != 0) {
            printWriter.print(str);
            printWriter.print("getPopExitAnim=");
            printWriter.println(G());
        }
        if (this.f4763I != null) {
            printWriter.print(str);
            printWriter.print("mContainer=");
            printWriter.println(this.f4763I);
        }
        if (this.f4764J != null) {
            printWriter.print(str);
            printWriter.print("mView=");
            printWriter.println(this.f4764J);
        }
        if (l() != null) {
            printWriter.print(str);
            printWriter.print("mAnimatingAway=");
            printWriter.println(l());
        }
        if (o() != null) {
            androidx.loader.app.a.b(this).a(str, fileDescriptor, printWriter, strArr);
        }
        printWriter.print(str);
        printWriter.println("Child " + this.f4804w + ":");
        this.f4804w.W(str + "  ", fileDescriptor, printWriter, strArr);
    }

    public void e0(int i3, int i4, Intent intent) {
        if (x.G0(2)) {
            Log.v("FragmentManager", "Fragment " + this + " received the following in onActivityResult(): requestCode: " + i3 + " resultCode: " + i4 + " data: " + intent);
        }
    }

    void e1(Bundle bundle) {
        F0(bundle);
        this.f4778X.e(bundle);
        Bundle bundleH1 = this.f4804w.O0();
        if (bundleH1 != null) {
            bundle.putParcelable("android:support:fragments", bundleH1);
        }
    }

    public final boolean equals(Object obj) {
        return super.equals(obj);
    }

    public void f0(Activity activity) {
        this.f4762H = true;
    }

    void f1() {
        this.f4804w.U0();
        this.f4804w.a0(true);
        this.f4782b = 5;
        this.f4762H = false;
        G0();
        if (!this.f4762H) {
            throw new N("Fragment " + this + " did not call through to super.onStart()");
        }
        androidx.lifecycle.l lVar = this.f4774T;
        f.a aVar = f.a.ON_START;
        lVar.h(aVar);
        if (this.f4764J != null) {
            this.f4775U.c(aVar);
        }
        this.f4804w.R();
    }

    Fragment g(String str) {
        return str.equals(this.f4788g) ? this : this.f4804w.i0(str);
    }

    public void g0(Context context) {
        this.f4762H = true;
        p pVar = this.f4803v;
        Activity activityI = pVar == null ? null : pVar.i();
        if (activityI != null) {
            this.f4762H = false;
            f0(activityI);
        }
    }

    void g1() {
        this.f4804w.T();
        if (this.f4764J != null) {
            this.f4775U.c(f.a.ON_STOP);
        }
        this.f4774T.h(f.a.ON_STOP);
        this.f4782b = 4;
        this.f4762H = false;
        H0();
        if (this.f4762H) {
            return;
        }
        throw new N("Fragment " + this + " did not call through to super.onStop()");
    }

    public final AbstractActivityC0298j h() {
        p pVar = this.f4803v;
        if (pVar == null) {
            return null;
        }
        return (AbstractActivityC0298j) pVar.i();
    }

    public void h0(Fragment fragment) {
    }

    void h1() {
        I0(this.f4764J, this.f4784c);
        this.f4804w.U();
    }

    public final int hashCode() {
        return super.hashCode();
    }

    public boolean i() {
        Boolean bool;
        f fVar = this.f4767M;
        if (fVar == null || (bool = fVar.f4831q) == null) {
            return true;
        }
        return bool.booleanValue();
    }

    public boolean i0(MenuItem menuItem) {
        return false;
    }

    public boolean j() {
        Boolean bool;
        f fVar = this.f4767M;
        if (fVar == null || (bool = fVar.f4830p) == null) {
            return true;
        }
        return bool.booleanValue();
    }

    public void j0(Bundle bundle) {
        this.f4762H = true;
        n1(bundle);
        if (this.f4804w.M0(1)) {
            return;
        }
        this.f4804w.B();
    }

    public final AbstractActivityC0298j j1() {
        AbstractActivityC0298j abstractActivityC0298jH = h();
        if (abstractActivityC0298jH != null) {
            return abstractActivityC0298jH;
        }
        throw new IllegalStateException("Fragment " + this + " not attached to an activity.");
    }

    @Override // androidx.lifecycle.InterfaceC0307e
    public E.a k() {
        Application application;
        Context applicationContext = l1().getApplicationContext();
        while (true) {
            if (!(applicationContext instanceof ContextWrapper)) {
                application = null;
                break;
            }
            if (applicationContext instanceof Application) {
                application = (Application) applicationContext;
                break;
            }
            applicationContext = ((ContextWrapper) applicationContext).getBaseContext();
        }
        if (application == null && x.G0(3)) {
            Log.d("FragmentManager", "Could not find Application instance from Context " + l1().getApplicationContext() + ", you will not be able to use AndroidViewModel with the default ViewModelProvider.Factory");
        }
        E.d dVar = new E.d();
        if (application != null) {
            dVar.b(z.a.f5190e, application);
        }
        dVar.b(androidx.lifecycle.v.f5173a, this);
        dVar.b(androidx.lifecycle.v.f5174b, this);
        if (m() != null) {
            dVar.b(androidx.lifecycle.v.f5175c, m());
        }
        return dVar;
    }

    public Animation k0(int i3, boolean z3, int i4) {
        return null;
    }

    public final Bundle k1() {
        Bundle bundleM = m();
        if (bundleM != null) {
            return bundleM;
        }
        throw new IllegalStateException("Fragment " + this + " does not have any arguments.");
    }

    View l() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        return fVar.f4815a;
    }

    public Animator l0(int i3, boolean z3, int i4) {
        return null;
    }

    public final Context l1() {
        Context contextO = o();
        if (contextO != null) {
            return contextO;
        }
        throw new IllegalStateException("Fragment " + this + " not attached to a context.");
    }

    public final Bundle m() {
        return this.f4789h;
    }

    public void m0(Menu menu, MenuInflater menuInflater) {
    }

    public final View m1() {
        View viewQ = Q();
        if (viewQ != null) {
            return viewQ;
        }
        throw new IllegalStateException("Fragment " + this + " did not return a View from onCreateView() or this was called before onCreateView().");
    }

    public final x n() {
        if (this.f4803v != null) {
            return this.f4804w;
        }
        throw new IllegalStateException("Fragment " + this + " has not been attached yet.");
    }

    public View n0(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        int i3 = this.f4779Y;
        if (i3 != 0) {
            return layoutInflater.inflate(i3, viewGroup, false);
        }
        return null;
    }

    void n1(Bundle bundle) {
        Parcelable parcelable;
        if (bundle == null || (parcelable = bundle.getParcelable("android:support:fragments")) == null) {
            return;
        }
        this.f4804w.f1(parcelable);
        this.f4804w.B();
    }

    public Context o() {
        p pVar = this.f4803v;
        if (pVar == null) {
            return null;
        }
        return pVar.k();
    }

    public void o0() {
        this.f4762H = true;
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        this.f4762H = true;
    }

    @Override // android.view.View.OnCreateContextMenuListener
    public void onCreateContextMenu(ContextMenu contextMenu, View view, ContextMenu.ContextMenuInfo contextMenuInfo) {
        j1().onCreateContextMenu(contextMenu, view, contextMenuInfo);
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
        this.f4762H = true;
    }

    int p() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return 0;
        }
        return fVar.f4817c;
    }

    public void p0() {
    }

    final void p1(Bundle bundle) {
        SparseArray<Parcelable> sparseArray = this.f4785d;
        if (sparseArray != null) {
            this.f4764J.restoreHierarchyState(sparseArray);
            this.f4785d = null;
        }
        if (this.f4764J != null) {
            this.f4775U.f(this.f4786e);
            this.f4786e = null;
        }
        this.f4762H = false;
        J0(bundle);
        if (this.f4762H) {
            if (this.f4764J != null) {
                this.f4775U.c(f.a.ON_CREATE);
            }
        } else {
            throw new N("Fragment " + this + " did not call through to super.onViewStateRestored()");
        }
    }

    public Object q() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        return fVar.f4824j;
    }

    public void q0() {
        this.f4762H = true;
    }

    void q1(int i3, int i4, int i5, int i6) {
        if (this.f4767M == null && i3 == 0 && i4 == 0 && i5 == 0 && i6 == 0) {
            return;
        }
        f().f4817c = i3;
        f().f4818d = i4;
        f().f4819e = i5;
        f().f4820f = i6;
    }

    @Override // androidx.lifecycle.C
    public androidx.lifecycle.B r() {
        if (this.f4802u == null) {
            throw new IllegalStateException("Can't access ViewModels from detached fragment");
        }
        if (A() != f.b.INITIALIZED.ordinal()) {
            return this.f4802u.B0(this);
        }
        throw new IllegalStateException("Calling getViewModelStore() before a Fragment reaches onCreate() when using setMaxLifecycle(INITIALIZED) is not supported");
    }

    public void r0() {
        this.f4762H = true;
    }

    public void r1(Bundle bundle) {
        if (this.f4802u != null && b0()) {
            throw new IllegalStateException("Fragment already added and state has been saved");
        }
        this.f4789h = bundle;
    }

    @Override // androidx.lifecycle.k
    public androidx.lifecycle.f s() {
        return this.f4774T;
    }

    public LayoutInflater s0(Bundle bundle) {
        return z(bundle);
    }

    void s1(View view) {
        f().f4833s = view;
    }

    androidx.core.app.m t() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        fVar.getClass();
        return null;
    }

    public void t0(boolean z3) {
    }

    void t1(int i3) {
        if (this.f4767M == null && i3 == 0) {
            return;
        }
        f();
        this.f4767M.f4821g = i3;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append(getClass().getSimpleName());
        sb.append("{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("}");
        sb.append(" (");
        sb.append(this.f4788g);
        if (this.f4806y != 0) {
            sb.append(" id=0x");
            sb.append(Integer.toHexString(this.f4806y));
        }
        if (this.f4755A != null) {
            sb.append(" tag=");
            sb.append(this.f4755A);
        }
        sb.append(")");
        return sb.toString();
    }

    int u() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return 0;
        }
        return fVar.f4818d;
    }

    public void u0(Activity activity, AttributeSet attributeSet, Bundle bundle) {
        this.f4762H = true;
    }

    void u1(boolean z3) {
        if (this.f4767M == null) {
            return;
        }
        f().f4816b = z3;
    }

    public Object v() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        return fVar.f4826l;
    }

    public void v0(Context context, AttributeSet attributeSet, Bundle bundle) {
        this.f4762H = true;
        p pVar = this.f4803v;
        Activity activityI = pVar == null ? null : pVar.i();
        if (activityI != null) {
            this.f4762H = false;
            u0(activityI, attributeSet, bundle);
        }
    }

    void v1(float f3) {
        f().f4832r = f3;
    }

    androidx.core.app.m w() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        fVar.getClass();
        return null;
    }

    public void w0(boolean z3) {
    }

    void w1(ArrayList arrayList, ArrayList arrayList2) {
        f();
        f fVar = this.f4767M;
        fVar.f4822h = arrayList;
        fVar.f4823i = arrayList2;
    }

    View x() {
        f fVar = this.f4767M;
        if (fVar == null) {
            return null;
        }
        return fVar.f4833s;
    }

    public boolean x0(MenuItem menuItem) {
        return false;
    }

    public void x1() {
        if (this.f4767M == null || !f().f4834t) {
            return;
        }
        if (this.f4803v == null) {
            f().f4834t = false;
        } else if (Looper.myLooper() != this.f4803v.o().getLooper()) {
            this.f4803v.o().postAtFrontOfQueue(new c());
        } else {
            c(true);
        }
    }

    public final Object y() {
        p pVar = this.f4803v;
        if (pVar == null) {
            return null;
        }
        return pVar.x();
    }

    public void y0(Menu menu) {
    }

    public LayoutInflater z(Bundle bundle) {
        p pVar = this.f4803v;
        if (pVar == null) {
            throw new IllegalStateException("onGetLayoutInflater() cannot be executed until the Fragment is attached to the FragmentManager.");
        }
        LayoutInflater layoutInflaterY = pVar.y();
        AbstractC0283u.a(layoutInflaterY, this.f4804w.u0());
        return layoutInflaterY;
    }

    public void z0() {
        this.f4762H = true;
    }
}
