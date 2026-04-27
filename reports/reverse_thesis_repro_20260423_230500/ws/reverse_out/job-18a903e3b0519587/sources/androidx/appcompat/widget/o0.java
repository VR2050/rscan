package androidx.appcompat.widget;

import android.text.TextUtils;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.accessibility.AccessibilityManager;

/* JADX INFO: loaded from: classes.dex */
class o0 implements View.OnLongClickListener, View.OnHoverListener, View.OnAttachStateChangeListener {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static o0 f4138l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static o0 f4139m;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View f4140b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final CharSequence f4141c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f4142d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Runnable f4143e = new Runnable() { // from class: androidx.appcompat.widget.m0
        @Override // java.lang.Runnable
        public final void run() {
            this.f4134b.e();
        }
    };

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Runnable f4144f = new Runnable() { // from class: androidx.appcompat.widget.n0
        @Override // java.lang.Runnable
        public final void run() {
            this.f4137b.d();
        }
    };

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f4145g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f4146h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private p0 f4147i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f4148j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f4149k;

    private o0(View view, CharSequence charSequence) {
        this.f4140b = view;
        this.f4141c = charSequence;
        this.f4142d = androidx.core.view.Z.e(ViewConfiguration.get(view.getContext()));
        c();
        view.setOnLongClickListener(this);
        view.setOnHoverListener(this);
    }

    private void b() {
        this.f4140b.removeCallbacks(this.f4143e);
    }

    private void c() {
        this.f4149k = true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void e() {
        i(false);
    }

    private void f() {
        this.f4140b.postDelayed(this.f4143e, ViewConfiguration.getLongPressTimeout());
    }

    private static void g(o0 o0Var) {
        o0 o0Var2 = f4138l;
        if (o0Var2 != null) {
            o0Var2.b();
        }
        f4138l = o0Var;
        if (o0Var != null) {
            o0Var.f();
        }
    }

    public static void h(View view, CharSequence charSequence) {
        o0 o0Var = f4138l;
        if (o0Var != null && o0Var.f4140b == view) {
            g(null);
        }
        if (!TextUtils.isEmpty(charSequence)) {
            new o0(view, charSequence);
            return;
        }
        o0 o0Var2 = f4139m;
        if (o0Var2 != null && o0Var2.f4140b == view) {
            o0Var2.d();
        }
        view.setOnLongClickListener(null);
        view.setLongClickable(false);
        view.setOnHoverListener(null);
    }

    private boolean j(MotionEvent motionEvent) {
        int x3 = (int) motionEvent.getX();
        int y3 = (int) motionEvent.getY();
        if (!this.f4149k && Math.abs(x3 - this.f4145g) <= this.f4142d && Math.abs(y3 - this.f4146h) <= this.f4142d) {
            return false;
        }
        this.f4145g = x3;
        this.f4146h = y3;
        this.f4149k = false;
        return true;
    }

    void d() {
        if (f4139m == this) {
            f4139m = null;
            p0 p0Var = this.f4147i;
            if (p0Var != null) {
                p0Var.c();
                this.f4147i = null;
                c();
                this.f4140b.removeOnAttachStateChangeListener(this);
            } else {
                Log.e("TooltipCompatHandler", "sActiveHandler.mPopup == null");
            }
        }
        if (f4138l == this) {
            g(null);
        }
        this.f4140b.removeCallbacks(this.f4144f);
    }

    void i(boolean z3) {
        long longPressTimeout;
        long j3;
        long j4;
        if (this.f4140b.isAttachedToWindow()) {
            g(null);
            o0 o0Var = f4139m;
            if (o0Var != null) {
                o0Var.d();
            }
            f4139m = this;
            this.f4148j = z3;
            p0 p0Var = new p0(this.f4140b.getContext());
            this.f4147i = p0Var;
            p0Var.e(this.f4140b, this.f4145g, this.f4146h, this.f4148j, this.f4141c);
            this.f4140b.addOnAttachStateChangeListener(this);
            if (this.f4148j) {
                j4 = 2500;
            } else {
                if ((androidx.core.view.V.B(this.f4140b) & 1) == 1) {
                    longPressTimeout = ViewConfiguration.getLongPressTimeout();
                    j3 = 3000;
                } else {
                    longPressTimeout = ViewConfiguration.getLongPressTimeout();
                    j3 = 15000;
                }
                j4 = j3 - longPressTimeout;
            }
            this.f4140b.removeCallbacks(this.f4144f);
            this.f4140b.postDelayed(this.f4144f, j4);
        }
    }

    @Override // android.view.View.OnHoverListener
    public boolean onHover(View view, MotionEvent motionEvent) {
        if (this.f4147i != null && this.f4148j) {
            return false;
        }
        AccessibilityManager accessibilityManager = (AccessibilityManager) this.f4140b.getContext().getSystemService("accessibility");
        if (accessibilityManager.isEnabled() && accessibilityManager.isTouchExplorationEnabled()) {
            return false;
        }
        int action = motionEvent.getAction();
        if (action != 7) {
            if (action == 10) {
                c();
                d();
            }
        } else if (this.f4140b.isEnabled() && this.f4147i == null && j(motionEvent)) {
            g(this);
        }
        return false;
    }

    @Override // android.view.View.OnLongClickListener
    public boolean onLongClick(View view) {
        this.f4145g = view.getWidth() / 2;
        this.f4146h = view.getHeight() / 2;
        i(true);
        return true;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewAttachedToWindow(View view) {
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewDetachedFromWindow(View view) {
        d();
    }
}
