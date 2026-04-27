package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import androidx.appcompat.view.menu.j;
import androidx.core.view.AbstractC0265g0;
import androidx.core.view.C0261e0;
import d.AbstractC0502a;
import e.AbstractC0510a;
import i.C0566a;

/* JADX INFO: loaded from: classes.dex */
public class k0 implements J {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    Toolbar f4103a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f4104b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private View f4105c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private View f4106d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Drawable f4107e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Drawable f4108f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Drawable f4109g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f4110h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    CharSequence f4111i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private CharSequence f4112j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private CharSequence f4113k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    Window.Callback f4114l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    boolean f4115m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private C0229c f4116n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f4117o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f4118p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Drawable f4119q;

    class a implements View.OnClickListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final C0566a f4120b;

        a() {
            this.f4120b = new C0566a(k0.this.f4103a.getContext(), 0, R.id.home, 0, 0, k0.this.f4111i);
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            k0 k0Var = k0.this;
            Window.Callback callback = k0Var.f4114l;
            if (callback == null || !k0Var.f4115m) {
                return;
            }
            callback.onMenuItemSelected(0, this.f4120b);
        }
    }

    class b extends AbstractC0265g0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f4122a = false;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f4123b;

        b(int i3) {
            this.f4123b = i3;
        }

        @Override // androidx.core.view.AbstractC0265g0, androidx.core.view.InterfaceC0263f0
        public void a(View view) {
            this.f4122a = true;
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void b(View view) {
            if (this.f4122a) {
                return;
            }
            k0.this.f4103a.setVisibility(this.f4123b);
        }

        @Override // androidx.core.view.AbstractC0265g0, androidx.core.view.InterfaceC0263f0
        public void c(View view) {
            k0.this.f4103a.setVisibility(0);
        }
    }

    public k0(Toolbar toolbar, boolean z3) {
        this(toolbar, z3, d.h.f8928a, d.e.f8865n);
    }

    private void E(CharSequence charSequence) {
        this.f4111i = charSequence;
        if ((this.f4104b & 8) != 0) {
            this.f4103a.setTitle(charSequence);
            if (this.f4110h) {
                androidx.core.view.V.a0(this.f4103a.getRootView(), charSequence);
            }
        }
    }

    private void F() {
        if ((this.f4104b & 4) != 0) {
            if (TextUtils.isEmpty(this.f4113k)) {
                this.f4103a.setNavigationContentDescription(this.f4118p);
            } else {
                this.f4103a.setNavigationContentDescription(this.f4113k);
            }
        }
    }

    private void G() {
        if ((this.f4104b & 4) == 0) {
            this.f4103a.setNavigationIcon((Drawable) null);
            return;
        }
        Toolbar toolbar = this.f4103a;
        Drawable drawable = this.f4109g;
        if (drawable == null) {
            drawable = this.f4119q;
        }
        toolbar.setNavigationIcon(drawable);
    }

    private void H() {
        Drawable drawable;
        int i3 = this.f4104b;
        if ((i3 & 2) == 0) {
            drawable = null;
        } else if ((i3 & 1) == 0 || (drawable = this.f4108f) == null) {
            drawable = this.f4107e;
        }
        this.f4103a.setLogo(drawable);
    }

    private int v() {
        if (this.f4103a.getNavigationIcon() == null) {
            return 11;
        }
        this.f4119q = this.f4103a.getNavigationIcon();
        return 15;
    }

    public void A(CharSequence charSequence) {
        this.f4113k = charSequence;
        F();
    }

    public void B(Drawable drawable) {
        this.f4109g = drawable;
        G();
    }

    public void C(CharSequence charSequence) {
        this.f4112j = charSequence;
        if ((this.f4104b & 8) != 0) {
            this.f4103a.setSubtitle(charSequence);
        }
    }

    public void D(CharSequence charSequence) {
        this.f4110h = true;
        E(charSequence);
    }

    @Override // androidx.appcompat.widget.J
    public void a(Menu menu, j.a aVar) {
        if (this.f4116n == null) {
            C0229c c0229c = new C0229c(this.f4103a.getContext());
            this.f4116n = c0229c;
            c0229c.p(d.f.f8890g);
        }
        this.f4116n.k(aVar);
        this.f4103a.M((androidx.appcompat.view.menu.e) menu, this.f4116n);
    }

    @Override // androidx.appcompat.widget.J
    public boolean b() {
        return this.f4103a.D();
    }

    @Override // androidx.appcompat.widget.J
    public Context c() {
        return this.f4103a.getContext();
    }

    @Override // androidx.appcompat.widget.J
    public void collapseActionView() {
        this.f4103a.f();
    }

    @Override // androidx.appcompat.widget.J
    public void d() {
        this.f4115m = true;
    }

    @Override // androidx.appcompat.widget.J
    public boolean e() {
        return this.f4103a.C();
    }

    @Override // androidx.appcompat.widget.J
    public boolean f() {
        return this.f4103a.y();
    }

    @Override // androidx.appcompat.widget.J
    public boolean g() {
        return this.f4103a.R();
    }

    @Override // androidx.appcompat.widget.J
    public CharSequence getTitle() {
        return this.f4103a.getTitle();
    }

    @Override // androidx.appcompat.widget.J
    public boolean h() {
        return this.f4103a.e();
    }

    @Override // androidx.appcompat.widget.J
    public void i() {
        this.f4103a.g();
    }

    @Override // androidx.appcompat.widget.J
    public void j(int i3) {
        this.f4103a.setVisibility(i3);
    }

    @Override // androidx.appcompat.widget.J
    public void k(a0 a0Var) {
        View view = this.f4105c;
        if (view != null) {
            ViewParent parent = view.getParent();
            Toolbar toolbar = this.f4103a;
            if (parent == toolbar) {
                toolbar.removeView(this.f4105c);
            }
        }
        this.f4105c = a0Var;
    }

    @Override // androidx.appcompat.widget.J
    public void l(boolean z3) {
    }

    @Override // androidx.appcompat.widget.J
    public boolean m() {
        return this.f4103a.x();
    }

    @Override // androidx.appcompat.widget.J
    public void n(int i3) {
        View view;
        int i4 = this.f4104b ^ i3;
        this.f4104b = i3;
        if (i4 != 0) {
            if ((i4 & 4) != 0) {
                if ((i3 & 4) != 0) {
                    F();
                }
                G();
            }
            if ((i4 & 3) != 0) {
                H();
            }
            if ((i4 & 8) != 0) {
                if ((i3 & 8) != 0) {
                    this.f4103a.setTitle(this.f4111i);
                    this.f4103a.setSubtitle(this.f4112j);
                } else {
                    this.f4103a.setTitle((CharSequence) null);
                    this.f4103a.setSubtitle((CharSequence) null);
                }
            }
            if ((i4 & 16) == 0 || (view = this.f4106d) == null) {
                return;
            }
            if ((i3 & 16) != 0) {
                this.f4103a.addView(view);
            } else {
                this.f4103a.removeView(view);
            }
        }
    }

    @Override // androidx.appcompat.widget.J
    public int o() {
        return this.f4104b;
    }

    @Override // androidx.appcompat.widget.J
    public void p(int i3) {
        y(i3 != 0 ? AbstractC0510a.b(c(), i3) : null);
    }

    @Override // androidx.appcompat.widget.J
    public int q() {
        return this.f4117o;
    }

    @Override // androidx.appcompat.widget.J
    public C0261e0 r(int i3, long j3) {
        return androidx.core.view.V.c(this.f4103a).b(i3 == 0 ? 1.0f : 0.0f).f(j3).h(new b(i3));
    }

    @Override // androidx.appcompat.widget.J
    public void s() {
        Log.i("ToolbarWidgetWrapper", "Progress display unsupported");
    }

    @Override // androidx.appcompat.widget.J
    public void setIcon(int i3) {
        setIcon(i3 != 0 ? AbstractC0510a.b(c(), i3) : null);
    }

    @Override // androidx.appcompat.widget.J
    public void setWindowCallback(Window.Callback callback) {
        this.f4114l = callback;
    }

    @Override // androidx.appcompat.widget.J
    public void setWindowTitle(CharSequence charSequence) {
        if (this.f4110h) {
            return;
        }
        E(charSequence);
    }

    @Override // androidx.appcompat.widget.J
    public void t() {
        Log.i("ToolbarWidgetWrapper", "Progress display unsupported");
    }

    @Override // androidx.appcompat.widget.J
    public void u(boolean z3) {
        this.f4103a.setCollapsible(z3);
    }

    public void w(View view) {
        View view2 = this.f4106d;
        if (view2 != null && (this.f4104b & 16) != 0) {
            this.f4103a.removeView(view2);
        }
        this.f4106d = view;
        if (view == null || (this.f4104b & 16) == 0) {
            return;
        }
        this.f4103a.addView(view);
    }

    public void x(int i3) {
        if (i3 == this.f4118p) {
            return;
        }
        this.f4118p = i3;
        if (TextUtils.isEmpty(this.f4103a.getNavigationContentDescription())) {
            z(this.f4118p);
        }
    }

    public void y(Drawable drawable) {
        this.f4108f = drawable;
        H();
    }

    public void z(int i3) {
        A(i3 == 0 ? null : c().getString(i3));
    }

    public k0(Toolbar toolbar, boolean z3, int i3, int i4) {
        Drawable drawable;
        this.f4117o = 0;
        this.f4118p = 0;
        this.f4103a = toolbar;
        this.f4111i = toolbar.getTitle();
        this.f4112j = toolbar.getSubtitle();
        this.f4110h = this.f4111i != null;
        this.f4109g = toolbar.getNavigationIcon();
        g0 g0VarU = g0.u(toolbar.getContext(), null, d.j.f9042a, AbstractC0502a.f8791c, 0);
        this.f4119q = g0VarU.f(d.j.f9086l);
        if (z3) {
            CharSequence charSequenceO = g0VarU.o(d.j.f9110r);
            if (!TextUtils.isEmpty(charSequenceO)) {
                D(charSequenceO);
            }
            CharSequence charSequenceO2 = g0VarU.o(d.j.f9102p);
            if (!TextUtils.isEmpty(charSequenceO2)) {
                C(charSequenceO2);
            }
            Drawable drawableF = g0VarU.f(d.j.f9094n);
            if (drawableF != null) {
                y(drawableF);
            }
            Drawable drawableF2 = g0VarU.f(d.j.f9090m);
            if (drawableF2 != null) {
                setIcon(drawableF2);
            }
            if (this.f4109g == null && (drawable = this.f4119q) != null) {
                B(drawable);
            }
            n(g0VarU.j(d.j.f9070h, 0));
            int iM = g0VarU.m(d.j.f9066g, 0);
            if (iM != 0) {
                w(LayoutInflater.from(this.f4103a.getContext()).inflate(iM, (ViewGroup) this.f4103a, false));
                n(this.f4104b | 16);
            }
            int iL = g0VarU.l(d.j.f9078j, 0);
            if (iL > 0) {
                ViewGroup.LayoutParams layoutParams = this.f4103a.getLayoutParams();
                layoutParams.height = iL;
                this.f4103a.setLayoutParams(layoutParams);
            }
            int iD = g0VarU.d(d.j.f9062f, -1);
            int iD2 = g0VarU.d(d.j.f9058e, -1);
            if (iD >= 0 || iD2 >= 0) {
                this.f4103a.L(Math.max(iD, 0), Math.max(iD2, 0));
            }
            int iM2 = g0VarU.m(d.j.f9114s, 0);
            if (iM2 != 0) {
                Toolbar toolbar2 = this.f4103a;
                toolbar2.O(toolbar2.getContext(), iM2);
            }
            int iM3 = g0VarU.m(d.j.f9106q, 0);
            if (iM3 != 0) {
                Toolbar toolbar3 = this.f4103a;
                toolbar3.N(toolbar3.getContext(), iM3);
            }
            int iM4 = g0VarU.m(d.j.f9098o, 0);
            if (iM4 != 0) {
                this.f4103a.setPopupTheme(iM4);
            }
        } else {
            this.f4104b = v();
        }
        g0VarU.w();
        x(i3);
        this.f4113k = this.f4103a.getNavigationContentDescription();
        this.f4103a.setNavigationOnClickListener(new a());
    }

    @Override // androidx.appcompat.widget.J
    public void setIcon(Drawable drawable) {
        this.f4107e = drawable;
        H();
    }
}
