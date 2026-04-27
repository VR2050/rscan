package androidx.appcompat.view.menu;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.AdapterView;
import android.widget.FrameLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.appcompat.view.menu.j;
import androidx.appcompat.widget.W;

/* JADX INFO: loaded from: classes.dex */
final class l extends h implements PopupWindow.OnDismissListener, AdapterView.OnItemClickListener, j, View.OnKeyListener {

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private static final int f3566w = d.g.f8922m;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Context f3567c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final e f3568d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final d f3569e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f3570f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final int f3571g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f3572h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f3573i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    final W f3574j;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private PopupWindow.OnDismissListener f3577m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private View f3578n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    View f3579o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private j.a f3580p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    ViewTreeObserver f3581q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f3582r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f3583s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private int f3584t;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f3586v;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final ViewTreeObserver.OnGlobalLayoutListener f3575k = new a();

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final View.OnAttachStateChangeListener f3576l = new b();

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private int f3585u = 0;

    class a implements ViewTreeObserver.OnGlobalLayoutListener {
        a() {
        }

        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            if (!l.this.a() || l.this.f3574j.x()) {
                return;
            }
            View view = l.this.f3579o;
            if (view == null || !view.isShown()) {
                l.this.dismiss();
            } else {
                l.this.f3574j.b();
            }
        }
    }

    class b implements View.OnAttachStateChangeListener {
        b() {
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewAttachedToWindow(View view) {
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewDetachedFromWindow(View view) {
            ViewTreeObserver viewTreeObserver = l.this.f3581q;
            if (viewTreeObserver != null) {
                if (!viewTreeObserver.isAlive()) {
                    l.this.f3581q = view.getViewTreeObserver();
                }
                l lVar = l.this;
                lVar.f3581q.removeGlobalOnLayoutListener(lVar.f3575k);
            }
            view.removeOnAttachStateChangeListener(this);
        }
    }

    public l(Context context, e eVar, View view, int i3, int i4, boolean z3) {
        this.f3567c = context;
        this.f3568d = eVar;
        this.f3570f = z3;
        this.f3569e = new d(eVar, LayoutInflater.from(context), z3, f3566w);
        this.f3572h = i3;
        this.f3573i = i4;
        Resources resources = context.getResources();
        this.f3571g = Math.max(resources.getDisplayMetrics().widthPixels / 2, resources.getDimensionPixelSize(d.d.f8825b));
        this.f3578n = view;
        this.f3574j = new W(context, null, i3, i4);
        eVar.c(this, context);
    }

    private boolean z() {
        View view;
        if (a()) {
            return true;
        }
        if (this.f3582r || (view = this.f3578n) == null) {
            return false;
        }
        this.f3579o = view;
        this.f3574j.G(this);
        this.f3574j.H(this);
        this.f3574j.F(true);
        View view2 = this.f3579o;
        boolean z3 = this.f3581q == null;
        ViewTreeObserver viewTreeObserver = view2.getViewTreeObserver();
        this.f3581q = viewTreeObserver;
        if (z3) {
            viewTreeObserver.addOnGlobalLayoutListener(this.f3575k);
        }
        view2.addOnAttachStateChangeListener(this.f3576l);
        this.f3574j.z(view2);
        this.f3574j.C(this.f3585u);
        if (!this.f3583s) {
            this.f3584t = h.o(this.f3569e, null, this.f3567c, this.f3571g);
            this.f3583s = true;
        }
        this.f3574j.B(this.f3584t);
        this.f3574j.E(2);
        this.f3574j.D(n());
        this.f3574j.b();
        ListView listViewG = this.f3574j.g();
        listViewG.setOnKeyListener(this);
        if (this.f3586v && this.f3568d.x() != null) {
            FrameLayout frameLayout = (FrameLayout) LayoutInflater.from(this.f3567c).inflate(d.g.f8921l, (ViewGroup) listViewG, false);
            TextView textView = (TextView) frameLayout.findViewById(R.id.title);
            if (textView != null) {
                textView.setText(this.f3568d.x());
            }
            frameLayout.setEnabled(false);
            listViewG.addHeaderView(frameLayout, null, false);
        }
        this.f3574j.p(this.f3569e);
        this.f3574j.b();
        return true;
    }

    @Override // i.e
    public boolean a() {
        return !this.f3582r && this.f3574j.a();
    }

    @Override // i.e
    public void b() {
        if (!z()) {
            throw new IllegalStateException("StandardMenuPopup cannot be used without an anchor");
        }
    }

    @Override // androidx.appcompat.view.menu.j
    public void c(e eVar, boolean z3) {
        if (eVar != this.f3568d) {
            return;
        }
        dismiss();
        j.a aVar = this.f3580p;
        if (aVar != null) {
            aVar.c(eVar, z3);
        }
    }

    @Override // i.e
    public void dismiss() {
        if (a()) {
            this.f3574j.dismiss();
        }
    }

    @Override // androidx.appcompat.view.menu.j
    public boolean e(m mVar) {
        if (mVar.hasVisibleItems()) {
            i iVar = new i(this.f3567c, mVar, this.f3579o, this.f3570f, this.f3572h, this.f3573i);
            iVar.j(this.f3580p);
            iVar.g(h.x(mVar));
            iVar.i(this.f3577m);
            this.f3577m = null;
            this.f3568d.e(false);
            int iC = this.f3574j.c();
            int iN = this.f3574j.n();
            if ((Gravity.getAbsoluteGravity(this.f3585u, this.f3578n.getLayoutDirection()) & 7) == 5) {
                iC += this.f3578n.getWidth();
            }
            if (iVar.n(iC, iN)) {
                j.a aVar = this.f3580p;
                if (aVar == null) {
                    return true;
                }
                aVar.d(mVar);
                return true;
            }
        }
        return false;
    }

    @Override // androidx.appcompat.view.menu.j
    public void f(boolean z3) {
        this.f3583s = false;
        d dVar = this.f3569e;
        if (dVar != null) {
            dVar.notifyDataSetChanged();
        }
    }

    @Override // i.e
    public ListView g() {
        return this.f3574j.g();
    }

    @Override // androidx.appcompat.view.menu.j
    public boolean h() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.j
    public void k(j.a aVar) {
        this.f3580p = aVar;
    }

    @Override // androidx.appcompat.view.menu.h
    public void l(e eVar) {
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public void onDismiss() {
        this.f3582r = true;
        this.f3568d.close();
        ViewTreeObserver viewTreeObserver = this.f3581q;
        if (viewTreeObserver != null) {
            if (!viewTreeObserver.isAlive()) {
                this.f3581q = this.f3579o.getViewTreeObserver();
            }
            this.f3581q.removeGlobalOnLayoutListener(this.f3575k);
            this.f3581q = null;
        }
        this.f3579o.removeOnAttachStateChangeListener(this.f3576l);
        PopupWindow.OnDismissListener onDismissListener = this.f3577m;
        if (onDismissListener != null) {
            onDismissListener.onDismiss();
        }
    }

    @Override // android.view.View.OnKeyListener
    public boolean onKey(View view, int i3, KeyEvent keyEvent) {
        if (keyEvent.getAction() != 1 || i3 != 82) {
            return false;
        }
        dismiss();
        return true;
    }

    @Override // androidx.appcompat.view.menu.h
    public void p(View view) {
        this.f3578n = view;
    }

    @Override // androidx.appcompat.view.menu.h
    public void r(boolean z3) {
        this.f3569e.d(z3);
    }

    @Override // androidx.appcompat.view.menu.h
    public void s(int i3) {
        this.f3585u = i3;
    }

    @Override // androidx.appcompat.view.menu.h
    public void t(int i3) {
        this.f3574j.l(i3);
    }

    @Override // androidx.appcompat.view.menu.h
    public void u(PopupWindow.OnDismissListener onDismissListener) {
        this.f3577m = onDismissListener;
    }

    @Override // androidx.appcompat.view.menu.h
    public void v(boolean z3) {
        this.f3586v = z3;
    }

    @Override // androidx.appcompat.view.menu.h
    public void w(int i3) {
        this.f3574j.j(i3);
    }
}
