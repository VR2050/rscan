package androidx.fragment.app;

import android.app.Activity;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.core.view.V;
import androidx.fragment.app.L;
import androidx.lifecycle.f;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
class D {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final r f4714a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final E f4715b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Fragment f4716c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f4717d = false;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f4718e = -1;

    class a implements View.OnAttachStateChangeListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ View f4719b;

        a(View view) {
            this.f4719b = view;
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewAttachedToWindow(View view) {
            this.f4719b.removeOnAttachStateChangeListener(this);
            V.U(this.f4719b);
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewDetachedFromWindow(View view) {
        }
    }

    static /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f4721a;

        static {
            int[] iArr = new int[f.b.values().length];
            f4721a = iArr;
            try {
                iArr[f.b.RESUMED.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f4721a[f.b.STARTED.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f4721a[f.b.CREATED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f4721a[f.b.INITIALIZED.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    D(r rVar, E e3, Fragment fragment) {
        this.f4714a = rVar;
        this.f4715b = e3;
        this.f4716c = fragment;
    }

    private boolean l(View view) {
        if (view == this.f4716c.f4764J) {
            return true;
        }
        for (ViewParent parent = view.getParent(); parent != null; parent = parent.getParent()) {
            if (parent == this.f4716c.f4764J) {
                return true;
            }
        }
        return false;
    }

    private Bundle q() {
        Bundle bundle = new Bundle();
        this.f4716c.e1(bundle);
        this.f4714a.j(this.f4716c, bundle, false);
        if (bundle.isEmpty()) {
            bundle = null;
        }
        if (this.f4716c.f4764J != null) {
            s();
        }
        if (this.f4716c.f4785d != null) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putSparseParcelableArray("android:view_state", this.f4716c.f4785d);
        }
        if (this.f4716c.f4786e != null) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putBundle("android:view_registry_state", this.f4716c.f4786e);
        }
        if (!this.f4716c.f4766L) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putBoolean("android:user_visible_hint", this.f4716c.f4766L);
        }
        return bundle;
    }

    void a() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto ACTIVITY_CREATED: " + this.f4716c);
        }
        Fragment fragment = this.f4716c;
        fragment.K0(fragment.f4784c);
        r rVar = this.f4714a;
        Fragment fragment2 = this.f4716c;
        rVar.a(fragment2, fragment2.f4784c, false);
    }

    void b() {
        int iJ = this.f4715b.j(this.f4716c);
        Fragment fragment = this.f4716c;
        fragment.f4763I.addView(fragment.f4764J, iJ);
    }

    void c() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto ATTACHED: " + this.f4716c);
        }
        Fragment fragment = this.f4716c;
        Fragment fragment2 = fragment.f4790i;
        D dN = null;
        if (fragment2 != null) {
            D dN2 = this.f4715b.n(fragment2.f4788g);
            if (dN2 == null) {
                throw new IllegalStateException("Fragment " + this.f4716c + " declared target fragment " + this.f4716c.f4790i + " that does not belong to this FragmentManager!");
            }
            Fragment fragment3 = this.f4716c;
            fragment3.f4791j = fragment3.f4790i.f4788g;
            fragment3.f4790i = null;
            dN = dN2;
        } else {
            String str = fragment.f4791j;
            if (str != null && (dN = this.f4715b.n(str)) == null) {
                throw new IllegalStateException("Fragment " + this.f4716c + " declared target fragment " + this.f4716c.f4791j + " that does not belong to this FragmentManager!");
            }
        }
        if (dN != null) {
            dN.m();
        }
        Fragment fragment4 = this.f4716c;
        fragment4.f4803v = fragment4.f4802u.t0();
        Fragment fragment5 = this.f4716c;
        fragment5.f4805x = fragment5.f4802u.w0();
        this.f4714a.g(this.f4716c, false);
        this.f4716c.L0();
        this.f4714a.b(this.f4716c, false);
    }

    int d() {
        Fragment fragment = this.f4716c;
        if (fragment.f4802u == null) {
            return fragment.f4782b;
        }
        int iMin = this.f4718e;
        int i3 = b.f4721a[fragment.f4773S.ordinal()];
        if (i3 != 1) {
            iMin = i3 != 2 ? i3 != 3 ? i3 != 4 ? Math.min(iMin, -1) : Math.min(iMin, 0) : Math.min(iMin, 1) : Math.min(iMin, 5);
        }
        Fragment fragment2 = this.f4716c;
        if (fragment2.f4797p) {
            if (fragment2.f4798q) {
                iMin = Math.max(this.f4718e, 2);
                View view = this.f4716c.f4764J;
                if (view != null && view.getParent() == null) {
                    iMin = Math.min(iMin, 2);
                }
            } else {
                iMin = this.f4718e < 4 ? Math.min(iMin, fragment2.f4782b) : Math.min(iMin, 1);
            }
        }
        if (!this.f4716c.f4794m) {
            iMin = Math.min(iMin, 1);
        }
        Fragment fragment3 = this.f4716c;
        ViewGroup viewGroup = fragment3.f4763I;
        L.e.b bVarL = viewGroup != null ? L.n(viewGroup, fragment3.D()).l(this) : null;
        if (bVarL == L.e.b.ADDING) {
            iMin = Math.min(iMin, 6);
        } else if (bVarL == L.e.b.REMOVING) {
            iMin = Math.max(iMin, 3);
        } else {
            Fragment fragment4 = this.f4716c;
            if (fragment4.f4795n) {
                iMin = fragment4.X() ? Math.min(iMin, 1) : Math.min(iMin, -1);
            }
        }
        Fragment fragment5 = this.f4716c;
        if (fragment5.f4765K && fragment5.f4782b < 5) {
            iMin = Math.min(iMin, 4);
        }
        if (x.G0(2)) {
            Log.v("FragmentManager", "computeExpectedState() of " + iMin + " for " + this.f4716c);
        }
        return iMin;
    }

    void e() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto CREATED: " + this.f4716c);
        }
        Fragment fragment = this.f4716c;
        if (fragment.f4771Q) {
            fragment.n1(fragment.f4784c);
            this.f4716c.f4782b = 1;
            return;
        }
        this.f4714a.h(fragment, fragment.f4784c, false);
        Fragment fragment2 = this.f4716c;
        fragment2.O0(fragment2.f4784c);
        r rVar = this.f4714a;
        Fragment fragment3 = this.f4716c;
        rVar.c(fragment3, fragment3.f4784c, false);
    }

    void f() {
        String resourceName;
        if (this.f4716c.f4797p) {
            return;
        }
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto CREATE_VIEW: " + this.f4716c);
        }
        Fragment fragment = this.f4716c;
        LayoutInflater layoutInflaterU0 = fragment.U0(fragment.f4784c);
        Fragment fragment2 = this.f4716c;
        ViewGroup viewGroup = fragment2.f4763I;
        if (viewGroup == null) {
            int i3 = fragment2.f4807z;
            if (i3 == 0) {
                viewGroup = null;
            } else {
                if (i3 == -1) {
                    throw new IllegalArgumentException("Cannot create fragment " + this.f4716c + " for a container view with no id");
                }
                viewGroup = (ViewGroup) fragment2.f4802u.p0().f(this.f4716c.f4807z);
                if (viewGroup == null) {
                    Fragment fragment3 = this.f4716c;
                    if (!fragment3.f4799r) {
                        try {
                            resourceName = fragment3.J().getResourceName(this.f4716c.f4807z);
                        } catch (Resources.NotFoundException unused) {
                            resourceName = "unknown";
                        }
                        throw new IllegalArgumentException("No view found for id 0x" + Integer.toHexString(this.f4716c.f4807z) + " (" + resourceName + ") for fragment " + this.f4716c);
                    }
                } else if (!(viewGroup instanceof C0301m)) {
                    B.c.i(this.f4716c, viewGroup);
                }
            }
        }
        Fragment fragment4 = this.f4716c;
        fragment4.f4763I = viewGroup;
        fragment4.Q0(layoutInflaterU0, viewGroup, fragment4.f4784c);
        View view = this.f4716c.f4764J;
        if (view != null) {
            view.setSaveFromParentEnabled(false);
            Fragment fragment5 = this.f4716c;
            fragment5.f4764J.setTag(A.b.f6a, fragment5);
            if (viewGroup != null) {
                b();
            }
            Fragment fragment6 = this.f4716c;
            if (fragment6.f4756B) {
                fragment6.f4764J.setVisibility(8);
            }
            if (V.E(this.f4716c.f4764J)) {
                V.U(this.f4716c.f4764J);
            } else {
                View view2 = this.f4716c.f4764J;
                view2.addOnAttachStateChangeListener(new a(view2));
            }
            this.f4716c.h1();
            r rVar = this.f4714a;
            Fragment fragment7 = this.f4716c;
            rVar.m(fragment7, fragment7.f4764J, fragment7.f4784c, false);
            int visibility = this.f4716c.f4764J.getVisibility();
            this.f4716c.v1(this.f4716c.f4764J.getAlpha());
            Fragment fragment8 = this.f4716c;
            if (fragment8.f4763I != null && visibility == 0) {
                View viewFindFocus = fragment8.f4764J.findFocus();
                if (viewFindFocus != null) {
                    this.f4716c.s1(viewFindFocus);
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "requestFocus: Saved focused view " + viewFindFocus + " for Fragment " + this.f4716c);
                    }
                }
                this.f4716c.f4764J.setAlpha(0.0f);
            }
        }
        this.f4716c.f4782b = 2;
    }

    void g() {
        Fragment fragmentF;
        if (x.G0(3)) {
            Log.d("FragmentManager", "movefrom CREATED: " + this.f4716c);
        }
        Fragment fragment = this.f4716c;
        boolean zIsChangingConfigurations = true;
        boolean z3 = fragment.f4795n && !fragment.X();
        if (z3) {
            Fragment fragment2 = this.f4716c;
            if (!fragment2.f4796o) {
                this.f4715b.B(fragment2.f4788g, null);
            }
        }
        if (!z3 && !this.f4715b.p().q(this.f4716c)) {
            String str = this.f4716c.f4791j;
            if (str != null && (fragmentF = this.f4715b.f(str)) != null && fragmentF.f4758D) {
                this.f4716c.f4790i = fragmentF;
            }
            this.f4716c.f4782b = 0;
            return;
        }
        p pVar = this.f4716c.f4803v;
        if (pVar instanceof androidx.lifecycle.C) {
            zIsChangingConfigurations = this.f4715b.p().n();
        } else if (pVar.k() instanceof Activity) {
            zIsChangingConfigurations = true ^ ((Activity) pVar.k()).isChangingConfigurations();
        }
        if ((z3 && !this.f4716c.f4796o) || zIsChangingConfigurations) {
            this.f4715b.p().f(this.f4716c);
        }
        this.f4716c.R0();
        this.f4714a.d(this.f4716c, false);
        for (D d3 : this.f4715b.k()) {
            if (d3 != null) {
                Fragment fragmentK = d3.k();
                if (this.f4716c.f4788g.equals(fragmentK.f4791j)) {
                    fragmentK.f4790i = this.f4716c;
                    fragmentK.f4791j = null;
                }
            }
        }
        Fragment fragment3 = this.f4716c;
        String str2 = fragment3.f4791j;
        if (str2 != null) {
            fragment3.f4790i = this.f4715b.f(str2);
        }
        this.f4715b.s(this);
    }

    void h() {
        View view;
        if (x.G0(3)) {
            Log.d("FragmentManager", "movefrom CREATE_VIEW: " + this.f4716c);
        }
        Fragment fragment = this.f4716c;
        ViewGroup viewGroup = fragment.f4763I;
        if (viewGroup != null && (view = fragment.f4764J) != null) {
            viewGroup.removeView(view);
        }
        this.f4716c.S0();
        this.f4714a.n(this.f4716c, false);
        Fragment fragment2 = this.f4716c;
        fragment2.f4763I = null;
        fragment2.f4764J = null;
        fragment2.f4775U = null;
        fragment2.f4776V.i(null);
        this.f4716c.f4798q = false;
    }

    void i() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "movefrom ATTACHED: " + this.f4716c);
        }
        this.f4716c.T0();
        this.f4714a.e(this.f4716c, false);
        Fragment fragment = this.f4716c;
        fragment.f4782b = -1;
        fragment.f4803v = null;
        fragment.f4805x = null;
        fragment.f4802u = null;
        if ((!fragment.f4795n || fragment.X()) && !this.f4715b.p().q(this.f4716c)) {
            return;
        }
        if (x.G0(3)) {
            Log.d("FragmentManager", "initState called for fragment: " + this.f4716c);
        }
        this.f4716c.T();
    }

    void j() {
        Fragment fragment = this.f4716c;
        if (fragment.f4797p && fragment.f4798q && !fragment.f4800s) {
            if (x.G0(3)) {
                Log.d("FragmentManager", "moveto CREATE_VIEW: " + this.f4716c);
            }
            Fragment fragment2 = this.f4716c;
            fragment2.Q0(fragment2.U0(fragment2.f4784c), null, this.f4716c.f4784c);
            View view = this.f4716c.f4764J;
            if (view != null) {
                view.setSaveFromParentEnabled(false);
                Fragment fragment3 = this.f4716c;
                fragment3.f4764J.setTag(A.b.f6a, fragment3);
                Fragment fragment4 = this.f4716c;
                if (fragment4.f4756B) {
                    fragment4.f4764J.setVisibility(8);
                }
                this.f4716c.h1();
                r rVar = this.f4714a;
                Fragment fragment5 = this.f4716c;
                rVar.m(fragment5, fragment5.f4764J, fragment5.f4784c, false);
                this.f4716c.f4782b = 2;
            }
        }
    }

    Fragment k() {
        return this.f4716c;
    }

    void m() {
        ViewGroup viewGroup;
        ViewGroup viewGroup2;
        ViewGroup viewGroup3;
        if (this.f4717d) {
            if (x.G0(2)) {
                Log.v("FragmentManager", "Ignoring re-entrant call to moveToExpectedState() for " + k());
                return;
            }
            return;
        }
        try {
            this.f4717d = true;
            boolean z3 = false;
            while (true) {
                int iD = d();
                Fragment fragment = this.f4716c;
                int i3 = fragment.f4782b;
                if (iD == i3) {
                    if (!z3 && i3 == -1 && fragment.f4795n && !fragment.X() && !this.f4716c.f4796o) {
                        if (x.G0(3)) {
                            Log.d("FragmentManager", "Cleaning up state of never attached fragment: " + this.f4716c);
                        }
                        this.f4715b.p().f(this.f4716c);
                        this.f4715b.s(this);
                        if (x.G0(3)) {
                            Log.d("FragmentManager", "initState called for fragment: " + this.f4716c);
                        }
                        this.f4716c.T();
                    }
                    Fragment fragment2 = this.f4716c;
                    if (fragment2.f4769O) {
                        if (fragment2.f4764J != null && (viewGroup = fragment2.f4763I) != null) {
                            L lN = L.n(viewGroup, fragment2.D());
                            if (this.f4716c.f4756B) {
                                lN.c(this);
                            } else {
                                lN.e(this);
                            }
                        }
                        Fragment fragment3 = this.f4716c;
                        x xVar = fragment3.f4802u;
                        if (xVar != null) {
                            xVar.E0(fragment3);
                        }
                        Fragment fragment4 = this.f4716c;
                        fragment4.f4769O = false;
                        fragment4.t0(fragment4.f4756B);
                        this.f4716c.f4804w.I();
                    }
                    this.f4717d = false;
                    return;
                }
                if (iD <= i3) {
                    switch (i3 - 1) {
                        case -1:
                            i();
                            break;
                        case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
                            if (fragment.f4796o && this.f4715b.q(fragment.f4788g) == null) {
                                r();
                            }
                            g();
                            break;
                        case 1:
                            h();
                            this.f4716c.f4782b = 1;
                            break;
                        case 2:
                            fragment.f4798q = false;
                            fragment.f4782b = 2;
                            break;
                        case 3:
                            if (x.G0(3)) {
                                Log.d("FragmentManager", "movefrom ACTIVITY_CREATED: " + this.f4716c);
                            }
                            Fragment fragment5 = this.f4716c;
                            if (fragment5.f4796o) {
                                r();
                            } else if (fragment5.f4764J != null && fragment5.f4785d == null) {
                                s();
                            }
                            Fragment fragment6 = this.f4716c;
                            if (fragment6.f4764J != null && (viewGroup2 = fragment6.f4763I) != null) {
                                L.n(viewGroup2, fragment6.D()).d(this);
                            }
                            this.f4716c.f4782b = 3;
                            break;
                        case 4:
                            v();
                            break;
                        case 5:
                            fragment.f4782b = 5;
                            break;
                        case 6:
                            n();
                            break;
                    }
                } else {
                    switch (i3 + 1) {
                        case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
                            c();
                            break;
                        case 1:
                            e();
                            break;
                        case 2:
                            j();
                            f();
                            break;
                        case 3:
                            a();
                            break;
                        case 4:
                            if (fragment.f4764J != null && (viewGroup3 = fragment.f4763I) != null) {
                                L.n(viewGroup3, fragment.D()).b(L.e.c.b(this.f4716c.f4764J.getVisibility()), this);
                            }
                            this.f4716c.f4782b = 4;
                            break;
                        case 5:
                            u();
                            break;
                        case 6:
                            fragment.f4782b = 6;
                            break;
                        case 7:
                            p();
                            break;
                    }
                }
                z3 = true;
            }
        } catch (Throwable th) {
            this.f4717d = false;
            throw th;
        }
    }

    void n() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "movefrom RESUMED: " + this.f4716c);
        }
        this.f4716c.Z0();
        this.f4714a.f(this.f4716c, false);
    }

    void o(ClassLoader classLoader) {
        Bundle bundle = this.f4716c.f4784c;
        if (bundle == null) {
            return;
        }
        bundle.setClassLoader(classLoader);
        Fragment fragment = this.f4716c;
        fragment.f4785d = fragment.f4784c.getSparseParcelableArray("android:view_state");
        Fragment fragment2 = this.f4716c;
        fragment2.f4786e = fragment2.f4784c.getBundle("android:view_registry_state");
        Fragment fragment3 = this.f4716c;
        fragment3.f4791j = fragment3.f4784c.getString("android:target_state");
        Fragment fragment4 = this.f4716c;
        if (fragment4.f4791j != null) {
            fragment4.f4792k = fragment4.f4784c.getInt("android:target_req_state", 0);
        }
        Fragment fragment5 = this.f4716c;
        Boolean bool = fragment5.f4787f;
        if (bool != null) {
            fragment5.f4766L = bool.booleanValue();
            this.f4716c.f4787f = null;
        } else {
            fragment5.f4766L = fragment5.f4784c.getBoolean("android:user_visible_hint", true);
        }
        Fragment fragment6 = this.f4716c;
        if (fragment6.f4766L) {
            return;
        }
        fragment6.f4765K = true;
    }

    void p() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto RESUMED: " + this.f4716c);
        }
        View viewX = this.f4716c.x();
        if (viewX != null && l(viewX)) {
            boolean zRequestFocus = viewX.requestFocus();
            if (x.G0(2)) {
                StringBuilder sb = new StringBuilder();
                sb.append("requestFocus: Restoring focused view ");
                sb.append(viewX);
                sb.append(" ");
                sb.append(zRequestFocus ? "succeeded" : "failed");
                sb.append(" on Fragment ");
                sb.append(this.f4716c);
                sb.append(" resulting in focused view ");
                sb.append(this.f4716c.f4764J.findFocus());
                Log.v("FragmentManager", sb.toString());
            }
        }
        this.f4716c.s1(null);
        this.f4716c.d1();
        this.f4714a.i(this.f4716c, false);
        Fragment fragment = this.f4716c;
        fragment.f4784c = null;
        fragment.f4785d = null;
        fragment.f4786e = null;
    }

    void r() {
        C c3 = new C(this.f4716c);
        Fragment fragment = this.f4716c;
        if (fragment.f4782b <= -1 || c3.f4713m != null) {
            c3.f4713m = fragment.f4784c;
        } else {
            Bundle bundleQ = q();
            c3.f4713m = bundleQ;
            if (this.f4716c.f4791j != null) {
                if (bundleQ == null) {
                    c3.f4713m = new Bundle();
                }
                c3.f4713m.putString("android:target_state", this.f4716c.f4791j);
                int i3 = this.f4716c.f4792k;
                if (i3 != 0) {
                    c3.f4713m.putInt("android:target_req_state", i3);
                }
            }
        }
        this.f4715b.B(this.f4716c.f4788g, c3);
    }

    void s() {
        if (this.f4716c.f4764J == null) {
            return;
        }
        if (x.G0(2)) {
            Log.v("FragmentManager", "Saving view state for fragment " + this.f4716c + " with view " + this.f4716c.f4764J);
        }
        SparseArray<Parcelable> sparseArray = new SparseArray<>();
        this.f4716c.f4764J.saveHierarchyState(sparseArray);
        if (sparseArray.size() > 0) {
            this.f4716c.f4785d = sparseArray;
        }
        Bundle bundle = new Bundle();
        this.f4716c.f4775U.g(bundle);
        if (bundle.isEmpty()) {
            return;
        }
        this.f4716c.f4786e = bundle;
    }

    void t(int i3) {
        this.f4718e = i3;
    }

    void u() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "moveto STARTED: " + this.f4716c);
        }
        this.f4716c.f1();
        this.f4714a.k(this.f4716c, false);
    }

    void v() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "movefrom STARTED: " + this.f4716c);
        }
        this.f4716c.g1();
        this.f4714a.l(this.f4716c, false);
    }

    D(r rVar, E e3, ClassLoader classLoader, o oVar, C c3) {
        this.f4714a = rVar;
        this.f4715b = e3;
        Fragment fragmentA = c3.a(oVar, classLoader);
        this.f4716c = fragmentA;
        if (x.G0(2)) {
            Log.v("FragmentManager", "Instantiated fragment " + fragmentA);
        }
    }

    D(r rVar, E e3, Fragment fragment, C c3) {
        this.f4714a = rVar;
        this.f4715b = e3;
        this.f4716c = fragment;
        fragment.f4785d = null;
        fragment.f4786e = null;
        fragment.f4801t = 0;
        fragment.f4798q = false;
        fragment.f4794m = false;
        Fragment fragment2 = fragment.f4790i;
        fragment.f4791j = fragment2 != null ? fragment2.f4788g : null;
        fragment.f4790i = null;
        Bundle bundle = c3.f4713m;
        if (bundle != null) {
            fragment.f4784c = bundle;
        } else {
            fragment.f4784c = new Bundle();
        }
    }
}
