package androidx.appcompat.app;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import androidx.appcompat.view.b;
import androidx.appcompat.view.menu.e;
import androidx.appcompat.widget.ActionBarContainer;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.ActionBarOverlayLayout;
import androidx.appcompat.widget.J;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.AbstractC0265g0;
import androidx.core.view.C0261e0;
import androidx.core.view.InterfaceC0263f0;
import androidx.core.view.InterfaceC0267h0;
import androidx.core.view.V;
import d.AbstractC0502a;
import java.lang.ref.WeakReference;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public class z extends androidx.appcompat.app.a implements ActionBarOverlayLayout.d {

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private static final Interpolator f3281D = new AccelerateInterpolator();

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private static final Interpolator f3282E = new DecelerateInterpolator();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    Context f3286a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Context f3287b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Activity f3288c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    ActionBarOverlayLayout f3289d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    ActionBarContainer f3290e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    J f3291f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    ActionBarContextView f3292g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    View f3293h;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f3296k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    d f3297l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    androidx.appcompat.view.b f3298m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    b.a f3299n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f3300o;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private boolean f3302q;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    boolean f3305t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    boolean f3306u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f3307v;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    androidx.appcompat.view.h f3309x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private boolean f3310y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    boolean f3311z;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private ArrayList f3294i = new ArrayList();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f3295j = -1;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private ArrayList f3301p = new ArrayList();

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f3303r = 0;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    boolean f3304s = true;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f3308w = true;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    final InterfaceC0263f0 f3283A = new a();

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    final InterfaceC0263f0 f3284B = new b();

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    final InterfaceC0267h0 f3285C = new c();

    class a extends AbstractC0265g0 {
        a() {
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void b(View view) {
            View view2;
            z zVar = z.this;
            if (zVar.f3304s && (view2 = zVar.f3293h) != null) {
                view2.setTranslationY(0.0f);
                z.this.f3290e.setTranslationY(0.0f);
            }
            z.this.f3290e.setVisibility(8);
            z.this.f3290e.setTransitioning(false);
            z zVar2 = z.this;
            zVar2.f3309x = null;
            zVar2.x();
            ActionBarOverlayLayout actionBarOverlayLayout = z.this.f3289d;
            if (actionBarOverlayLayout != null) {
                V.U(actionBarOverlayLayout);
            }
        }
    }

    class b extends AbstractC0265g0 {
        b() {
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void b(View view) {
            z zVar = z.this;
            zVar.f3309x = null;
            zVar.f3290e.requestLayout();
        }
    }

    class c implements InterfaceC0267h0 {
        c() {
        }

        @Override // androidx.core.view.InterfaceC0267h0
        public void a(View view) {
            ((View) z.this.f3290e.getParent()).invalidate();
        }
    }

    public class d extends androidx.appcompat.view.b implements e.a {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Context f3315d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final androidx.appcompat.view.menu.e f3316e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private b.a f3317f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private WeakReference f3318g;

        public d(Context context, b.a aVar) {
            this.f3315d = context;
            this.f3317f = aVar;
            androidx.appcompat.view.menu.e eVarT = new androidx.appcompat.view.menu.e(context).T(1);
            this.f3316e = eVarT;
            eVarT.S(this);
        }

        @Override // androidx.appcompat.view.menu.e.a
        public boolean a(androidx.appcompat.view.menu.e eVar, MenuItem menuItem) {
            b.a aVar = this.f3317f;
            if (aVar != null) {
                return aVar.c(this, menuItem);
            }
            return false;
        }

        @Override // androidx.appcompat.view.menu.e.a
        public void b(androidx.appcompat.view.menu.e eVar) {
            if (this.f3317f == null) {
                return;
            }
            k();
            z.this.f3292g.l();
        }

        @Override // androidx.appcompat.view.b
        public void c() {
            z zVar = z.this;
            if (zVar.f3297l != this) {
                return;
            }
            if (z.w(zVar.f3305t, zVar.f3306u, false)) {
                this.f3317f.b(this);
            } else {
                z zVar2 = z.this;
                zVar2.f3298m = this;
                zVar2.f3299n = this.f3317f;
            }
            this.f3317f = null;
            z.this.v(false);
            z.this.f3292g.g();
            z zVar3 = z.this;
            zVar3.f3289d.setHideOnContentScrollEnabled(zVar3.f3311z);
            z.this.f3297l = null;
        }

        @Override // androidx.appcompat.view.b
        public View d() {
            WeakReference weakReference = this.f3318g;
            if (weakReference != null) {
                return (View) weakReference.get();
            }
            return null;
        }

        @Override // androidx.appcompat.view.b
        public Menu e() {
            return this.f3316e;
        }

        @Override // androidx.appcompat.view.b
        public MenuInflater f() {
            return new androidx.appcompat.view.g(this.f3315d);
        }

        @Override // androidx.appcompat.view.b
        public CharSequence g() {
            return z.this.f3292g.getSubtitle();
        }

        @Override // androidx.appcompat.view.b
        public CharSequence i() {
            return z.this.f3292g.getTitle();
        }

        @Override // androidx.appcompat.view.b
        public void k() {
            if (z.this.f3297l != this) {
                return;
            }
            this.f3316e.e0();
            try {
                this.f3317f.a(this, this.f3316e);
            } finally {
                this.f3316e.d0();
            }
        }

        @Override // androidx.appcompat.view.b
        public boolean l() {
            return z.this.f3292g.j();
        }

        @Override // androidx.appcompat.view.b
        public void m(View view) {
            z.this.f3292g.setCustomView(view);
            this.f3318g = new WeakReference(view);
        }

        @Override // androidx.appcompat.view.b
        public void n(int i3) {
            o(z.this.f3286a.getResources().getString(i3));
        }

        @Override // androidx.appcompat.view.b
        public void o(CharSequence charSequence) {
            z.this.f3292g.setSubtitle(charSequence);
        }

        @Override // androidx.appcompat.view.b
        public void q(int i3) {
            r(z.this.f3286a.getResources().getString(i3));
        }

        @Override // androidx.appcompat.view.b
        public void r(CharSequence charSequence) {
            z.this.f3292g.setTitle(charSequence);
        }

        @Override // androidx.appcompat.view.b
        public void s(boolean z3) {
            super.s(z3);
            z.this.f3292g.setTitleOptional(z3);
        }

        public boolean t() {
            this.f3316e.e0();
            try {
                return this.f3317f.d(this, this.f3316e);
            } finally {
                this.f3316e.d0();
            }
        }
    }

    public z(Activity activity, boolean z3) {
        this.f3288c = activity;
        View decorView = activity.getWindow().getDecorView();
        D(decorView);
        if (z3) {
            return;
        }
        this.f3293h = decorView.findViewById(R.id.content);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private J A(View view) {
        if (view instanceof J) {
            return (J) view;
        }
        if (view instanceof Toolbar) {
            return ((Toolbar) view).getWrapper();
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Can't make a decor toolbar out of ");
        sb.append(view != 0 ? view.getClass().getSimpleName() : "null");
        throw new IllegalStateException(sb.toString());
    }

    private void C() {
        if (this.f3307v) {
            this.f3307v = false;
            ActionBarOverlayLayout actionBarOverlayLayout = this.f3289d;
            if (actionBarOverlayLayout != null) {
                actionBarOverlayLayout.setShowingForActionMode(false);
            }
            M(false);
        }
    }

    private void D(View view) {
        ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) view.findViewById(d.f.f8899p);
        this.f3289d = actionBarOverlayLayout;
        if (actionBarOverlayLayout != null) {
            actionBarOverlayLayout.setActionBarVisibilityCallback(this);
        }
        this.f3291f = A(view.findViewById(d.f.f8884a));
        this.f3292g = (ActionBarContextView) view.findViewById(d.f.f8889f);
        ActionBarContainer actionBarContainer = (ActionBarContainer) view.findViewById(d.f.f8886c);
        this.f3290e = actionBarContainer;
        J j3 = this.f3291f;
        if (j3 == null || this.f3292g == null || actionBarContainer == null) {
            throw new IllegalStateException(getClass().getSimpleName() + " can only be used with a compatible window decor layout");
        }
        this.f3286a = j3.c();
        boolean z3 = (this.f3291f.o() & 4) != 0;
        if (z3) {
            this.f3296k = true;
        }
        androidx.appcompat.view.a aVarB = androidx.appcompat.view.a.b(this.f3286a);
        J(aVarB.a() || z3);
        H(aVarB.e());
        TypedArray typedArrayObtainStyledAttributes = this.f3286a.obtainStyledAttributes(null, d.j.f9042a, AbstractC0502a.f8791c, 0);
        if (typedArrayObtainStyledAttributes.getBoolean(d.j.f9082k, false)) {
            I(true);
        }
        int dimensionPixelSize = typedArrayObtainStyledAttributes.getDimensionPixelSize(d.j.f9074i, 0);
        if (dimensionPixelSize != 0) {
            G(dimensionPixelSize);
        }
        typedArrayObtainStyledAttributes.recycle();
    }

    private void H(boolean z3) {
        this.f3302q = z3;
        if (z3) {
            this.f3290e.setTabContainer(null);
            this.f3291f.k(null);
        } else {
            this.f3291f.k(null);
            this.f3290e.setTabContainer(null);
        }
        boolean z4 = false;
        boolean z5 = B() == 2;
        this.f3291f.u(!this.f3302q && z5);
        ActionBarOverlayLayout actionBarOverlayLayout = this.f3289d;
        if (!this.f3302q && z5) {
            z4 = true;
        }
        actionBarOverlayLayout.setHasNonEmbeddedTabs(z4);
    }

    private boolean K() {
        return this.f3290e.isLaidOut();
    }

    private void L() {
        if (this.f3307v) {
            return;
        }
        this.f3307v = true;
        ActionBarOverlayLayout actionBarOverlayLayout = this.f3289d;
        if (actionBarOverlayLayout != null) {
            actionBarOverlayLayout.setShowingForActionMode(true);
        }
        M(false);
    }

    private void M(boolean z3) {
        if (w(this.f3305t, this.f3306u, this.f3307v)) {
            if (this.f3308w) {
                return;
            }
            this.f3308w = true;
            z(z3);
            return;
        }
        if (this.f3308w) {
            this.f3308w = false;
            y(z3);
        }
    }

    static boolean w(boolean z3, boolean z4, boolean z5) {
        if (z5) {
            return true;
        }
        return (z3 || z4) ? false : true;
    }

    public int B() {
        return this.f3291f.q();
    }

    public void E(boolean z3) {
        F(z3 ? 4 : 0, 4);
    }

    public void F(int i3, int i4) {
        int iO = this.f3291f.o();
        if ((i4 & 4) != 0) {
            this.f3296k = true;
        }
        this.f3291f.n((i3 & i4) | ((~i4) & iO));
    }

    public void G(float f3) {
        V.e0(this.f3290e, f3);
    }

    public void I(boolean z3) {
        if (z3 && !this.f3289d.x()) {
            throw new IllegalStateException("Action bar must be in overlay mode (Window.FEATURE_OVERLAY_ACTION_BAR) to enable hide on content scroll");
        }
        this.f3311z = z3;
        this.f3289d.setHideOnContentScrollEnabled(z3);
    }

    public void J(boolean z3) {
        this.f3291f.l(z3);
    }

    @Override // androidx.appcompat.widget.ActionBarOverlayLayout.d
    public void a() {
        if (this.f3306u) {
            this.f3306u = false;
            M(true);
        }
    }

    @Override // androidx.appcompat.widget.ActionBarOverlayLayout.d
    public void b() {
        androidx.appcompat.view.h hVar = this.f3309x;
        if (hVar != null) {
            hVar.a();
            this.f3309x = null;
        }
    }

    @Override // androidx.appcompat.widget.ActionBarOverlayLayout.d
    public void c(int i3) {
        this.f3303r = i3;
    }

    @Override // androidx.appcompat.widget.ActionBarOverlayLayout.d
    public void d() {
    }

    @Override // androidx.appcompat.widget.ActionBarOverlayLayout.d
    public void e(boolean z3) {
        this.f3304s = z3;
    }

    @Override // androidx.appcompat.widget.ActionBarOverlayLayout.d
    public void f() {
        if (this.f3306u) {
            return;
        }
        this.f3306u = true;
        M(true);
    }

    @Override // androidx.appcompat.app.a
    public boolean h() {
        J j3 = this.f3291f;
        if (j3 == null || !j3.m()) {
            return false;
        }
        this.f3291f.collapseActionView();
        return true;
    }

    @Override // androidx.appcompat.app.a
    public void i(boolean z3) {
        if (z3 == this.f3300o) {
            return;
        }
        this.f3300o = z3;
        if (this.f3301p.size() <= 0) {
            return;
        }
        androidx.activity.result.d.a(this.f3301p.get(0));
        throw null;
    }

    @Override // androidx.appcompat.app.a
    public int j() {
        return this.f3291f.o();
    }

    @Override // androidx.appcompat.app.a
    public Context k() {
        if (this.f3287b == null) {
            TypedValue typedValue = new TypedValue();
            this.f3286a.getTheme().resolveAttribute(AbstractC0502a.f8793e, typedValue, true);
            int i3 = typedValue.resourceId;
            if (i3 != 0) {
                this.f3287b = new ContextThemeWrapper(this.f3286a, i3);
            } else {
                this.f3287b = this.f3286a;
            }
        }
        return this.f3287b;
    }

    @Override // androidx.appcompat.app.a
    public void m(Configuration configuration) {
        H(androidx.appcompat.view.a.b(this.f3286a).e());
    }

    @Override // androidx.appcompat.app.a
    public boolean o(int i3, KeyEvent keyEvent) {
        Menu menuE;
        d dVar = this.f3297l;
        if (dVar == null || (menuE = dVar.e()) == null) {
            return false;
        }
        menuE.setQwertyMode(KeyCharacterMap.load(keyEvent != null ? keyEvent.getDeviceId() : -1).getKeyboardType() != 1);
        return menuE.performShortcut(i3, keyEvent, 0);
    }

    @Override // androidx.appcompat.app.a
    public void r(boolean z3) {
        if (this.f3296k) {
            return;
        }
        E(z3);
    }

    @Override // androidx.appcompat.app.a
    public void s(boolean z3) {
        androidx.appcompat.view.h hVar;
        this.f3310y = z3;
        if (z3 || (hVar = this.f3309x) == null) {
            return;
        }
        hVar.a();
    }

    @Override // androidx.appcompat.app.a
    public void t(CharSequence charSequence) {
        this.f3291f.setWindowTitle(charSequence);
    }

    @Override // androidx.appcompat.app.a
    public androidx.appcompat.view.b u(b.a aVar) {
        d dVar = this.f3297l;
        if (dVar != null) {
            dVar.c();
        }
        this.f3289d.setHideOnContentScrollEnabled(false);
        this.f3292g.k();
        d dVar2 = new d(this.f3292g.getContext(), aVar);
        if (!dVar2.t()) {
            return null;
        }
        this.f3297l = dVar2;
        dVar2.k();
        this.f3292g.h(dVar2);
        v(true);
        return dVar2;
    }

    public void v(boolean z3) {
        C0261e0 c0261e0R;
        C0261e0 c0261e0F;
        if (z3) {
            L();
        } else {
            C();
        }
        if (!K()) {
            if (z3) {
                this.f3291f.j(4);
                this.f3292g.setVisibility(0);
                return;
            } else {
                this.f3291f.j(0);
                this.f3292g.setVisibility(8);
                return;
            }
        }
        if (z3) {
            c0261e0F = this.f3291f.r(4, 100L);
            c0261e0R = this.f3292g.f(0, 200L);
        } else {
            c0261e0R = this.f3291f.r(0, 200L);
            c0261e0F = this.f3292g.f(8, 100L);
        }
        androidx.appcompat.view.h hVar = new androidx.appcompat.view.h();
        hVar.d(c0261e0F, c0261e0R);
        hVar.h();
    }

    void x() {
        b.a aVar = this.f3299n;
        if (aVar != null) {
            aVar.b(this.f3298m);
            this.f3298m = null;
            this.f3299n = null;
        }
    }

    public void y(boolean z3) {
        View view;
        androidx.appcompat.view.h hVar = this.f3309x;
        if (hVar != null) {
            hVar.a();
        }
        if (this.f3303r != 0 || (!this.f3310y && !z3)) {
            this.f3283A.b(null);
            return;
        }
        this.f3290e.setAlpha(1.0f);
        this.f3290e.setTransitioning(true);
        androidx.appcompat.view.h hVar2 = new androidx.appcompat.view.h();
        float f3 = -this.f3290e.getHeight();
        if (z3) {
            this.f3290e.getLocationInWindow(new int[]{0, 0});
            f3 -= r5[1];
        }
        C0261e0 c0261e0M = V.c(this.f3290e).m(f3);
        c0261e0M.k(this.f3285C);
        hVar2.c(c0261e0M);
        if (this.f3304s && (view = this.f3293h) != null) {
            hVar2.c(V.c(view).m(f3));
        }
        hVar2.f(f3281D);
        hVar2.e(250L);
        hVar2.g(this.f3283A);
        this.f3309x = hVar2;
        hVar2.h();
    }

    public void z(boolean z3) {
        View view;
        View view2;
        androidx.appcompat.view.h hVar = this.f3309x;
        if (hVar != null) {
            hVar.a();
        }
        this.f3290e.setVisibility(0);
        if (this.f3303r == 0 && (this.f3310y || z3)) {
            this.f3290e.setTranslationY(0.0f);
            float f3 = -this.f3290e.getHeight();
            if (z3) {
                this.f3290e.getLocationInWindow(new int[]{0, 0});
                f3 -= r5[1];
            }
            this.f3290e.setTranslationY(f3);
            androidx.appcompat.view.h hVar2 = new androidx.appcompat.view.h();
            C0261e0 c0261e0M = V.c(this.f3290e).m(0.0f);
            c0261e0M.k(this.f3285C);
            hVar2.c(c0261e0M);
            if (this.f3304s && (view2 = this.f3293h) != null) {
                view2.setTranslationY(f3);
                hVar2.c(V.c(this.f3293h).m(0.0f));
            }
            hVar2.f(f3282E);
            hVar2.e(250L);
            hVar2.g(this.f3284B);
            this.f3309x = hVar2;
            hVar2.h();
        } else {
            this.f3290e.setAlpha(1.0f);
            this.f3290e.setTranslationY(0.0f);
            if (this.f3304s && (view = this.f3293h) != null) {
                view.setTranslationY(0.0f);
            }
            this.f3284B.b(null);
        }
        ActionBarOverlayLayout actionBarOverlayLayout = this.f3289d;
        if (actionBarOverlayLayout != null) {
            V.U(actionBarOverlayLayout);
        }
    }

    public z(Dialog dialog) {
        D(dialog.getWindow().getDecorView());
    }
}
