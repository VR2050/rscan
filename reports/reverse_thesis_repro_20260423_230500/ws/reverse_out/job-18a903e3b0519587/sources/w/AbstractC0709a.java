package w;

import android.graphics.Rect;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import androidx.core.view.AbstractC0257c0;
import androidx.core.view.C0252a;
import androidx.core.view.V;
import java.util.ArrayList;
import java.util.List;
import l.h;
import r.v;
import r.w;
import r.x;
import w.AbstractC0710b;

/* JADX INFO: renamed from: w.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0709a extends C0252a {

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static final Rect f10239n = new Rect(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MIN_VALUE, Integer.MIN_VALUE);

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final AbstractC0710b.a f10240o = new C0151a();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final AbstractC0710b.InterfaceC0152b f10241p = new b();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final AccessibilityManager f10246h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final View f10247i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private c f10248j;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Rect f10242d = new Rect();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Rect f10243e = new Rect();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Rect f10244f = new Rect();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final int[] f10245g = new int[2];

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    int f10249k = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    int f10250l = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f10251m = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: w.a$a, reason: collision with other inner class name */
    static class C0151a implements AbstractC0710b.a {
        C0151a() {
        }

        @Override // w.AbstractC0710b.a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(v vVar, Rect rect) {
            vVar.m(rect);
        }
    }

    /* JADX INFO: renamed from: w.a$b */
    static class b implements AbstractC0710b.InterfaceC0152b {
        b() {
        }

        @Override // w.AbstractC0710b.InterfaceC0152b
        /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
        public v a(h hVar, int i3) {
            return (v) hVar.o(i3);
        }

        @Override // w.AbstractC0710b.InterfaceC0152b
        /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
        public int b(h hVar) {
            return hVar.n();
        }
    }

    /* JADX INFO: renamed from: w.a$c */
    private class c extends w {
        c() {
        }

        @Override // r.w
        public v b(int i3) {
            return v.e0(AbstractC0709a.this.F(i3));
        }

        @Override // r.w
        public v d(int i3) {
            int i4 = i3 == 2 ? AbstractC0709a.this.f10249k : AbstractC0709a.this.f10250l;
            if (i4 == Integer.MIN_VALUE) {
                return null;
            }
            return b(i4);
        }

        @Override // r.w
        public boolean f(int i3, int i4, Bundle bundle) {
            return AbstractC0709a.this.N(i3, i4, bundle);
        }
    }

    public AbstractC0709a(View view) {
        if (view == null) {
            throw new IllegalArgumentException("View may not be null");
        }
        this.f10247i = view;
        this.f10246h = (AccessibilityManager) view.getContext().getSystemService("accessibility");
        view.setFocusable(true);
        if (V.r(view) == 0) {
            V.f0(view, 1);
        }
    }

    private static Rect B(View view, int i3, Rect rect) {
        int width = view.getWidth();
        int height = view.getHeight();
        if (i3 == 17) {
            rect.set(width, 0, width, height);
        } else if (i3 == 33) {
            rect.set(0, height, width, height);
        } else if (i3 == 66) {
            rect.set(-1, 0, -1, height);
        } else {
            if (i3 != 130) {
                throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
            }
            rect.set(0, -1, width, -1);
        }
        return rect;
    }

    private boolean C(Rect rect) {
        if (rect == null || rect.isEmpty() || this.f10247i.getWindowVisibility() != 0) {
            return false;
        }
        Object parent = this.f10247i.getParent();
        while (parent instanceof View) {
            View view = (View) parent;
            if (view.getAlpha() <= 0.0f || view.getVisibility() != 0) {
                return false;
            }
            parent = view.getParent();
        }
        return parent != null;
    }

    private static int D(int i3) {
        if (i3 == 19) {
            return 33;
        }
        if (i3 != 21) {
            return i3 != 22 ? 130 : 66;
        }
        return 17;
    }

    private boolean E(int i3, Rect rect) {
        v vVar;
        h hVarX = x();
        int i4 = this.f10250l;
        v vVar2 = i4 == Integer.MIN_VALUE ? null : (v) hVarX.g(i4);
        if (i3 == 1 || i3 == 2) {
            vVar = (v) AbstractC0710b.d(hVarX, f10241p, f10240o, vVar2, i3, V.s(this.f10247i) == 1, false);
        } else {
            if (i3 != 17 && i3 != 33 && i3 != 66 && i3 != 130) {
                throw new IllegalArgumentException("direction must be one of {FOCUS_FORWARD, FOCUS_BACKWARD, FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
            }
            Rect rect2 = new Rect();
            int i5 = this.f10250l;
            if (i5 != Integer.MIN_VALUE) {
                y(i5, rect2);
            } else if (rect != null) {
                rect2.set(rect);
            } else {
                B(this.f10247i, i3, rect2);
            }
            vVar = (v) AbstractC0710b.c(hVarX, f10241p, f10240o, vVar2, rect2, i3);
        }
        return R(vVar != null ? hVarX.l(hVarX.k(vVar)) : Integer.MIN_VALUE);
    }

    private boolean O(int i3, int i4, Bundle bundle) {
        return i4 != 1 ? i4 != 2 ? i4 != 64 ? i4 != 128 ? H(i3, i4, bundle) : n(i3) : Q(i3) : o(i3) : R(i3);
    }

    private boolean P(int i3, Bundle bundle) {
        return V.P(this.f10247i, i3, bundle);
    }

    private boolean Q(int i3) {
        int i4;
        if (!this.f10246h.isEnabled() || !this.f10246h.isTouchExplorationEnabled() || (i4 = this.f10249k) == i3) {
            return false;
        }
        if (i4 != Integer.MIN_VALUE) {
            n(i4);
        }
        this.f10249k = i3;
        this.f10247i.invalidate();
        S(i3, 32768);
        return true;
    }

    private void T(int i3) {
        int i4 = this.f10251m;
        if (i4 == i3) {
            return;
        }
        this.f10251m = i3;
        S(i3, 128);
        S(i4, 256);
    }

    private boolean n(int i3) {
        if (this.f10249k != i3) {
            return false;
        }
        this.f10249k = Integer.MIN_VALUE;
        this.f10247i.invalidate();
        S(i3, 65536);
        return true;
    }

    private boolean p() {
        int i3 = this.f10250l;
        return i3 != Integer.MIN_VALUE && H(i3, 16, null);
    }

    private AccessibilityEvent q(int i3, int i4) {
        return i3 != -1 ? r(i3, i4) : s(i4);
    }

    private AccessibilityEvent r(int i3, int i4) {
        AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain(i4);
        v vVarF = F(i3);
        accessibilityEventObtain.getText().add(vVarF.E());
        accessibilityEventObtain.setContentDescription(vVarF.u());
        accessibilityEventObtain.setScrollable(vVarF.Y());
        accessibilityEventObtain.setPassword(vVarF.W());
        accessibilityEventObtain.setEnabled(vVarF.Q());
        accessibilityEventObtain.setChecked(vVarF.N());
        J(i3, accessibilityEventObtain);
        if (accessibilityEventObtain.getText().isEmpty() && accessibilityEventObtain.getContentDescription() == null) {
            throw new RuntimeException("Callbacks must add text or a content description in populateEventForVirtualViewId()");
        }
        accessibilityEventObtain.setClassName(vVarF.q());
        x.c(accessibilityEventObtain, this.f10247i, i3);
        accessibilityEventObtain.setPackageName(this.f10247i.getContext().getPackageName());
        return accessibilityEventObtain;
    }

    private AccessibilityEvent s(int i3) {
        AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain(i3);
        this.f10247i.onInitializeAccessibilityEvent(accessibilityEventObtain);
        return accessibilityEventObtain;
    }

    private v t(int i3) {
        v vVarC0 = v.c0();
        vVarC0.u0(true);
        vVarC0.v0(true);
        vVarC0.p0("android.view.View");
        Rect rect = f10239n;
        vVarC0.l0(rect);
        vVarC0.m0(rect);
        vVarC0.C0(this.f10247i);
        L(i3, vVarC0);
        if (vVarC0.E() == null && vVarC0.u() == null) {
            throw new RuntimeException("Callbacks must add text or a content description in populateNodeForVirtualViewId()");
        }
        vVarC0.m(this.f10243e);
        if (this.f10243e.equals(rect)) {
            throw new RuntimeException("Callbacks must set parent bounds in populateNodeForVirtualViewId()");
        }
        int iK = vVarC0.k();
        if ((iK & 64) != 0) {
            throw new RuntimeException("Callbacks must not add ACTION_ACCESSIBILITY_FOCUS in populateNodeForVirtualViewId()");
        }
        if ((iK & 128) != 0) {
            throw new RuntimeException("Callbacks must not add ACTION_CLEAR_ACCESSIBILITY_FOCUS in populateNodeForVirtualViewId()");
        }
        vVarC0.A0(this.f10247i.getContext().getPackageName());
        vVarC0.K0(this.f10247i, i3);
        if (this.f10249k == i3) {
            vVarC0.j0(true);
            vVarC0.a(128);
        } else {
            vVarC0.j0(false);
            vVarC0.a(64);
        }
        boolean z3 = this.f10250l == i3;
        if (z3) {
            vVarC0.a(2);
        } else if (vVarC0.R()) {
            vVarC0.a(1);
        }
        vVarC0.w0(z3);
        this.f10247i.getLocationOnScreen(this.f10245g);
        vVarC0.n(this.f10242d);
        if (this.f10242d.equals(rect)) {
            vVarC0.m(this.f10242d);
            if (vVarC0.f9928b != -1) {
                v vVarC02 = v.c0();
                for (int i4 = vVarC0.f9928b; i4 != -1; i4 = vVarC02.f9928b) {
                    vVarC02.D0(this.f10247i, -1);
                    vVarC02.l0(f10239n);
                    L(i4, vVarC02);
                    vVarC02.m(this.f10243e);
                    Rect rect2 = this.f10242d;
                    Rect rect3 = this.f10243e;
                    rect2.offset(rect3.left, rect3.top);
                }
                vVarC02.g0();
            }
            this.f10242d.offset(this.f10245g[0] - this.f10247i.getScrollX(), this.f10245g[1] - this.f10247i.getScrollY());
        }
        if (this.f10247i.getLocalVisibleRect(this.f10244f)) {
            this.f10244f.offset(this.f10245g[0] - this.f10247i.getScrollX(), this.f10245g[1] - this.f10247i.getScrollY());
            if (this.f10242d.intersect(this.f10244f)) {
                vVarC0.m0(this.f10242d);
                if (C(this.f10242d)) {
                    vVarC0.O0(true);
                }
            }
        }
        return vVarC0;
    }

    private v u() {
        v vVarD0 = v.d0(this.f10247i);
        V.N(this.f10247i, vVarD0);
        ArrayList arrayList = new ArrayList();
        A(arrayList);
        if (vVarD0.p() > 0 && arrayList.size() > 0) {
            throw new RuntimeException("Views cannot have both real and virtual children");
        }
        int size = arrayList.size();
        for (int i3 = 0; i3 < size; i3++) {
            vVarD0.d(this.f10247i, ((Integer) arrayList.get(i3)).intValue());
        }
        return vVarD0;
    }

    private h x() {
        ArrayList arrayList = new ArrayList();
        A(arrayList);
        h hVar = new h();
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            hVar.m(i3, t(i3));
        }
        return hVar;
    }

    private void y(int i3, Rect rect) {
        F(i3).m(rect);
    }

    protected abstract void A(List list);

    v F(int i3) {
        return i3 == -1 ? u() : t(i3);
    }

    public final void G(boolean z3, int i3, Rect rect) {
        int i4 = this.f10250l;
        if (i4 != Integer.MIN_VALUE) {
            o(i4);
        }
        if (z3) {
            E(i3, rect);
        }
    }

    protected abstract boolean H(int i3, int i4, Bundle bundle);

    protected abstract void L(int i3, v vVar);

    boolean N(int i3, int i4, Bundle bundle) {
        return i3 != -1 ? O(i3, i4, bundle) : P(i4, bundle);
    }

    public final boolean R(int i3) {
        int i4;
        if ((!this.f10247i.isFocused() && !this.f10247i.requestFocus()) || (i4 = this.f10250l) == i3) {
            return false;
        }
        if (i4 != Integer.MIN_VALUE) {
            o(i4);
        }
        this.f10250l = i3;
        M(i3, true);
        S(i3, 8);
        return true;
    }

    public final boolean S(int i3, int i4) {
        ViewParent parent;
        if (i3 == Integer.MIN_VALUE || !this.f10246h.isEnabled() || (parent = this.f10247i.getParent()) == null) {
            return false;
        }
        return AbstractC0257c0.h(parent, this.f10247i, q(i3, i4));
    }

    @Override // androidx.core.view.C0252a
    public w b(View view) {
        if (this.f10248j == null) {
            this.f10248j = new c();
        }
        return this.f10248j;
    }

    @Override // androidx.core.view.C0252a
    public void f(View view, AccessibilityEvent accessibilityEvent) {
        super.f(view, accessibilityEvent);
        I(accessibilityEvent);
    }

    @Override // androidx.core.view.C0252a
    public void g(View view, v vVar) {
        super.g(view, vVar);
        K(vVar);
    }

    public final boolean o(int i3) {
        if (this.f10250l != i3) {
            return false;
        }
        this.f10250l = Integer.MIN_VALUE;
        M(i3, false);
        S(i3, 8);
        return true;
    }

    public final boolean v(MotionEvent motionEvent) {
        if (!this.f10246h.isEnabled() || !this.f10246h.isTouchExplorationEnabled()) {
            return false;
        }
        int action = motionEvent.getAction();
        if (action == 7 || action == 9) {
            int iZ = z(motionEvent.getX(), motionEvent.getY());
            T(iZ);
            return iZ != Integer.MIN_VALUE;
        }
        if (action != 10 || this.f10251m == Integer.MIN_VALUE) {
            return false;
        }
        T(Integer.MIN_VALUE);
        return true;
    }

    public final boolean w(KeyEvent keyEvent) {
        int i3 = 0;
        if (keyEvent.getAction() == 1) {
            return false;
        }
        int keyCode = keyEvent.getKeyCode();
        if (keyCode == 61) {
            if (keyEvent.hasNoModifiers()) {
                return E(2, null);
            }
            if (keyEvent.hasModifiers(1)) {
                return E(1, null);
            }
            return false;
        }
        if (keyCode != 66) {
            switch (keyCode) {
                case 19:
                case 20:
                case 21:
                case 22:
                    if (!keyEvent.hasNoModifiers()) {
                        return false;
                    }
                    int iD = D(keyCode);
                    int repeatCount = keyEvent.getRepeatCount() + 1;
                    boolean z3 = false;
                    while (i3 < repeatCount && E(iD, null)) {
                        i3++;
                        z3 = true;
                    }
                    return z3;
                case 23:
                    break;
                default:
                    return false;
            }
        }
        if (!keyEvent.hasNoModifiers() || keyEvent.getRepeatCount() != 0) {
            return false;
        }
        p();
        return true;
    }

    protected abstract int z(float f3, float f4);

    protected void I(AccessibilityEvent accessibilityEvent) {
    }

    protected void K(v vVar) {
    }

    protected void J(int i3, AccessibilityEvent accessibilityEvent) {
    }

    protected void M(int i3, boolean z3) {
    }
}
