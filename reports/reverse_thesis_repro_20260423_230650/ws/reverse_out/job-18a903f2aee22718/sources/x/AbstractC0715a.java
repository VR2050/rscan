package x;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.SystemClock;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityEvent;
import androidx.core.view.AbstractC0281s;
import androidx.core.view.C0252a;
import androidx.core.view.V;
import java.util.ArrayList;
import java.util.List;
import r.v;
import v.AbstractC0704a;
import w.C0711c;

/* JADX INFO: renamed from: x.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0715a extends ViewGroup {

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private static final int[] f10307M = {R.attr.colorPrimaryDark};

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    static final int[] f10308N = {R.attr.layout_gravity};

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    static final boolean f10309O = true;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private static final boolean f10310P = true;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private Drawable f10311A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private CharSequence f10312B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private CharSequence f10313C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private Object f10314D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private boolean f10315E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private Drawable f10316F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private Drawable f10317G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private Drawable f10318H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private Drawable f10319I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private final ArrayList f10320J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private Rect f10321K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private Matrix f10322L;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final c f10323b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f10324c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f10325d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f10326e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float f10327f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Paint f10328g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final C0711c f10329h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final C0711c f10330i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final g f10331j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final g f10332k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f10333l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f10334m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f10335n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f10336o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f10337p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f10338q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f10339r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f10340s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f10341t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private d f10342u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private List f10343v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private float f10344w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private float f10345x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private Drawable f10346y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private Drawable f10347z;

    /* JADX INFO: renamed from: x.a$a, reason: collision with other inner class name */
    class ViewOnApplyWindowInsetsListenerC0156a implements View.OnApplyWindowInsetsListener {
        ViewOnApplyWindowInsetsListenerC0156a() {
        }

        @Override // android.view.View.OnApplyWindowInsetsListener
        public WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
            ((AbstractC0715a) view).Q(windowInsets, windowInsets.getSystemWindowInsetTop() > 0);
            return windowInsets.consumeSystemWindowInsets();
        }
    }

    /* JADX INFO: renamed from: x.a$b */
    class b extends C0252a {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Rect f10349d = new Rect();

        b() {
        }

        private void n(v vVar, ViewGroup viewGroup) {
            int childCount = viewGroup.getChildCount();
            for (int i3 = 0; i3 < childCount; i3++) {
                View childAt = viewGroup.getChildAt(i3);
                if (AbstractC0715a.A(childAt)) {
                    vVar.c(childAt);
                }
            }
        }

        private void o(v vVar, v vVar2) {
            Rect rect = this.f10349d;
            vVar2.m(rect);
            vVar.l0(rect);
            vVar2.n(rect);
            vVar.m0(rect);
            vVar.O0(vVar2.b0());
            vVar.A0(vVar2.A());
            vVar.p0(vVar2.q());
            vVar.t0(vVar2.u());
            vVar.u0(vVar2.Q());
            vVar.q0(vVar2.O());
            vVar.v0(vVar2.R());
            vVar.w0(vVar2.S());
            vVar.j0(vVar2.L());
            vVar.I0(vVar2.Z());
            vVar.z0(vVar2.V());
            vVar.a(vVar2.k());
        }

        @Override // androidx.core.view.C0252a
        public boolean a(View view, AccessibilityEvent accessibilityEvent) {
            if (accessibilityEvent.getEventType() != 32) {
                return super.a(view, accessibilityEvent);
            }
            List<CharSequence> text = accessibilityEvent.getText();
            View viewP = AbstractC0715a.this.p();
            if (viewP == null) {
                return true;
            }
            CharSequence charSequenceS = AbstractC0715a.this.s(AbstractC0715a.this.t(viewP));
            if (charSequenceS == null) {
                return true;
            }
            text.add(charSequenceS);
            return true;
        }

        @Override // androidx.core.view.C0252a
        public void f(View view, AccessibilityEvent accessibilityEvent) {
            super.f(view, accessibilityEvent);
            accessibilityEvent.setClassName(AbstractC0715a.class.getName());
        }

        @Override // androidx.core.view.C0252a
        public void g(View view, v vVar) {
            if (AbstractC0715a.f10309O) {
                super.g(view, vVar);
            } else {
                v vVarE0 = v.e0(vVar);
                super.g(view, vVarE0);
                vVar.J0(view);
                Object objX = V.x(view);
                if (objX instanceof View) {
                    vVar.C0((View) objX);
                }
                o(vVar, vVarE0);
                vVarE0.g0();
                n(vVar, (ViewGroup) view);
            }
            vVar.p0(AbstractC0715a.class.getName());
            vVar.v0(false);
            vVar.w0(false);
            vVar.h0(v.a.f9951d);
            vVar.h0(v.a.f9952e);
        }

        @Override // androidx.core.view.C0252a
        public boolean i(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
            if (AbstractC0715a.f10309O || AbstractC0715a.A(view)) {
                return super.i(viewGroup, view, accessibilityEvent);
            }
            return false;
        }
    }

    /* JADX INFO: renamed from: x.a$c */
    static final class c extends C0252a {
        c() {
        }

        @Override // androidx.core.view.C0252a
        public void g(View view, v vVar) {
            super.g(view, vVar);
            if (AbstractC0715a.A(view)) {
                return;
            }
            vVar.C0(null);
        }
    }

    /* JADX INFO: renamed from: x.a$d */
    public interface d {
        void a(int i3);

        void b(View view, float f3);

        void c(View view);

        void d(View view);
    }

    /* JADX INFO: renamed from: x.a$g */
    private class g extends C0711c.AbstractC0153c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f10360a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private C0711c f10361b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Runnable f10362c = new RunnableC0158a();

        /* JADX INFO: renamed from: x.a$g$a, reason: collision with other inner class name */
        class RunnableC0158a implements Runnable {
            RunnableC0158a() {
            }

            @Override // java.lang.Runnable
            public void run() {
                g.this.o();
            }
        }

        g(int i3) {
            this.f10360a = i3;
        }

        private void n() {
            View viewN = AbstractC0715a.this.n(this.f10360a == 3 ? 5 : 3);
            if (viewN != null) {
                AbstractC0715a.this.f(viewN);
            }
        }

        @Override // w.C0711c.AbstractC0153c
        public int a(View view, int i3, int i4) {
            if (AbstractC0715a.this.c(view, 3)) {
                return Math.max(-view.getWidth(), Math.min(i3, 0));
            }
            int width = AbstractC0715a.this.getWidth();
            return Math.max(width - view.getWidth(), Math.min(i3, width));
        }

        @Override // w.C0711c.AbstractC0153c
        public int b(View view, int i3, int i4) {
            return view.getTop();
        }

        @Override // w.C0711c.AbstractC0153c
        public int d(View view) {
            if (AbstractC0715a.this.D(view)) {
                return view.getWidth();
            }
            return 0;
        }

        @Override // w.C0711c.AbstractC0153c
        public void f(int i3, int i4) {
            View viewN = (i3 & 1) == 1 ? AbstractC0715a.this.n(3) : AbstractC0715a.this.n(5);
            if (viewN == null || AbstractC0715a.this.r(viewN) != 0) {
                return;
            }
            this.f10361b.b(viewN, i4);
        }

        @Override // w.C0711c.AbstractC0153c
        public boolean g(int i3) {
            return false;
        }

        @Override // w.C0711c.AbstractC0153c
        public void h(int i3, int i4) {
            AbstractC0715a.this.postDelayed(this.f10362c, 160L);
        }

        @Override // w.C0711c.AbstractC0153c
        public void i(View view, int i3) {
            ((e) view.getLayoutParams()).f10353c = false;
            n();
        }

        @Override // w.C0711c.AbstractC0153c
        public void j(int i3) {
            AbstractC0715a.this.U(this.f10360a, i3, this.f10361b.v());
        }

        @Override // w.C0711c.AbstractC0153c
        public void k(View view, int i3, int i4, int i5, int i6) {
            float width = (AbstractC0715a.this.c(view, 3) ? i3 + r3 : AbstractC0715a.this.getWidth() - i3) / view.getWidth();
            AbstractC0715a.this.S(view, width);
            view.setVisibility(width == 0.0f ? 4 : 0);
            AbstractC0715a.this.invalidate();
        }

        @Override // w.C0711c.AbstractC0153c
        public void l(View view, float f3, float f4) {
            int i3;
            float fU = AbstractC0715a.this.u(view);
            int width = view.getWidth();
            if (AbstractC0715a.this.c(view, 3)) {
                i3 = (f3 > 0.0f || (f3 == 0.0f && fU > 0.5f)) ? 0 : -width;
            } else {
                int width2 = AbstractC0715a.this.getWidth();
                if (f3 < 0.0f || (f3 == 0.0f && fU > 0.5f)) {
                    width2 -= width;
                }
                i3 = width2;
            }
            this.f10361b.M(i3, view.getTop());
            AbstractC0715a.this.invalidate();
        }

        @Override // w.C0711c.AbstractC0153c
        public boolean m(View view, int i3) {
            return AbstractC0715a.this.D(view) && AbstractC0715a.this.c(view, this.f10360a) && AbstractC0715a.this.r(view) == 0;
        }

        void o() {
            View viewN;
            int width;
            int iW = this.f10361b.w();
            boolean z3 = this.f10360a == 3;
            if (z3) {
                viewN = AbstractC0715a.this.n(3);
                width = (viewN != null ? -viewN.getWidth() : 0) + iW;
            } else {
                viewN = AbstractC0715a.this.n(5);
                width = AbstractC0715a.this.getWidth() - iW;
            }
            if (viewN != null) {
                if (((!z3 || viewN.getLeft() >= width) && (z3 || viewN.getLeft() <= width)) || AbstractC0715a.this.r(viewN) != 0) {
                    return;
                }
                e eVar = (e) viewN.getLayoutParams();
                this.f10361b.O(viewN, width, viewN.getTop());
                eVar.f10353c = true;
                AbstractC0715a.this.invalidate();
                n();
                AbstractC0715a.this.b();
            }
        }

        public void p() {
            AbstractC0715a.this.removeCallbacks(this.f10362c);
        }

        public void q(C0711c c0711c) {
            this.f10361b = c0711c;
        }
    }

    public AbstractC0715a(Context context) {
        this(context, null);
    }

    static boolean A(View view) {
        return (V.r(view) == 4 || V.r(view) == 2) ? false : true;
    }

    private boolean F(float f3, float f4, View view) {
        if (this.f10321K == null) {
            this.f10321K = new Rect();
        }
        view.getHitRect(this.f10321K);
        return this.f10321K.contains((int) f3, (int) f4);
    }

    private boolean G(Drawable drawable, int i3) {
        if (drawable == null || !androidx.core.graphics.drawable.a.a(drawable)) {
            return false;
        }
        androidx.core.graphics.drawable.a.e(drawable, i3);
        return true;
    }

    private Drawable N() {
        int iS = V.s(this);
        if (iS == 0) {
            Drawable drawable = this.f10316F;
            if (drawable != null) {
                G(drawable, iS);
                return this.f10316F;
            }
        } else {
            Drawable drawable2 = this.f10317G;
            if (drawable2 != null) {
                G(drawable2, iS);
                return this.f10317G;
            }
        }
        return this.f10318H;
    }

    private Drawable O() {
        int iS = V.s(this);
        if (iS == 0) {
            Drawable drawable = this.f10317G;
            if (drawable != null) {
                G(drawable, iS);
                return this.f10317G;
            }
        } else {
            Drawable drawable2 = this.f10316F;
            if (drawable2 != null) {
                G(drawable2, iS);
                return this.f10316F;
            }
        }
        return this.f10319I;
    }

    private void P() {
        if (f10310P) {
            return;
        }
        this.f10347z = N();
        this.f10311A = O();
    }

    private void T(View view, boolean z3) {
        int childCount = getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = getChildAt(i3);
            if ((z3 || D(childAt)) && !(z3 && childAt == view)) {
                V.f0(childAt, 4);
            } else {
                V.f0(childAt, 1);
            }
        }
    }

    private boolean m(MotionEvent motionEvent, View view) {
        if (!view.getMatrix().isIdentity()) {
            MotionEvent motionEventV = v(motionEvent, view);
            boolean zDispatchGenericMotionEvent = view.dispatchGenericMotionEvent(motionEventV);
            motionEventV.recycle();
            return zDispatchGenericMotionEvent;
        }
        float scrollX = getScrollX() - view.getLeft();
        float scrollY = getScrollY() - view.getTop();
        motionEvent.offsetLocation(scrollX, scrollY);
        boolean zDispatchGenericMotionEvent2 = view.dispatchGenericMotionEvent(motionEvent);
        motionEvent.offsetLocation(-scrollX, -scrollY);
        return zDispatchGenericMotionEvent2;
    }

    private MotionEvent v(MotionEvent motionEvent, View view) {
        float scrollX = getScrollX() - view.getLeft();
        float scrollY = getScrollY() - view.getTop();
        MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
        motionEventObtain.offsetLocation(scrollX, scrollY);
        Matrix matrix = view.getMatrix();
        if (!matrix.isIdentity()) {
            if (this.f10322L == null) {
                this.f10322L = new Matrix();
            }
            matrix.invert(this.f10322L);
            motionEventObtain.transform(this.f10322L);
        }
        return motionEventObtain;
    }

    static String w(int i3) {
        return (i3 & 3) == 3 ? "LEFT" : (i3 & 5) == 5 ? "RIGHT" : Integer.toHexString(i3);
    }

    private static boolean x(View view) {
        Drawable background = view.getBackground();
        return background != null && background.getOpacity() == -1;
    }

    private boolean y() {
        int childCount = getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            if (((e) getChildAt(i3).getLayoutParams()).f10353c) {
                return true;
            }
        }
        return false;
    }

    private boolean z() {
        return p() != null;
    }

    boolean B(View view) {
        return ((e) view.getLayoutParams()).f10351a == 0;
    }

    public boolean C(View view) {
        if (D(view)) {
            return (((e) view.getLayoutParams()).f10354d & 1) == 1;
        }
        throw new IllegalArgumentException("View " + view + " is not a drawer");
    }

    boolean D(View view) {
        int iA = AbstractC0281s.a(((e) view.getLayoutParams()).f10351a, V.s(view));
        return ((iA & 3) == 0 && (iA & 5) == 0) ? false : true;
    }

    public boolean E(View view) {
        if (D(view)) {
            return ((e) view.getLayoutParams()).f10352b > 0.0f;
        }
        throw new IllegalArgumentException("View " + view + " is not a drawer");
    }

    void H(View view, float f3) {
        float fU = u(view);
        float width = view.getWidth();
        int i3 = ((int) (width * f3)) - ((int) (fU * width));
        if (!c(view, 3)) {
            i3 = -i3;
        }
        view.offsetLeftAndRight(i3);
        S(view, f3);
    }

    public void I(int i3) {
        J(i3, true);
    }

    public void J(int i3, boolean z3) {
        View viewN = n(i3);
        if (viewN != null) {
            L(viewN, z3);
            return;
        }
        throw new IllegalArgumentException("No drawer view found with gravity " + w(i3));
    }

    public void K(View view) {
        L(view, true);
    }

    public void L(View view, boolean z3) {
        if (!D(view)) {
            throw new IllegalArgumentException("View " + view + " is not a sliding drawer");
        }
        e eVar = (e) view.getLayoutParams();
        if (this.f10335n) {
            eVar.f10352b = 1.0f;
            eVar.f10354d = 1;
            T(view, true);
        } else if (z3) {
            eVar.f10354d |= 2;
            if (c(view, 3)) {
                this.f10329h.O(view, 0, view.getTop());
            } else {
                this.f10330i.O(view, getWidth() - view.getWidth(), view.getTop());
            }
        } else {
            H(view, 1.0f);
            U(eVar.f10351a, 0, view);
            view.setVisibility(0);
        }
        invalidate();
    }

    public void M(d dVar) {
        List list;
        if (dVar == null || (list = this.f10343v) == null) {
            return;
        }
        list.remove(dVar);
    }

    public void Q(Object obj, boolean z3) {
        this.f10314D = obj;
        this.f10315E = z3;
        setWillNotDraw(!z3 && getBackground() == null);
        requestLayout();
    }

    public void R(int i3, int i4) {
        View viewN;
        int iA = AbstractC0281s.a(i4, V.s(this));
        if (i4 == 3) {
            this.f10336o = i3;
        } else if (i4 == 5) {
            this.f10337p = i3;
        } else if (i4 == 8388611) {
            this.f10338q = i3;
        } else if (i4 == 8388613) {
            this.f10339r = i3;
        }
        if (i3 != 0) {
            (iA == 3 ? this.f10329h : this.f10330i).a();
        }
        if (i3 != 1) {
            if (i3 == 2 && (viewN = n(iA)) != null) {
                K(viewN);
                return;
            }
            return;
        }
        View viewN2 = n(iA);
        if (viewN2 != null) {
            f(viewN2);
        }
    }

    void S(View view, float f3) {
        e eVar = (e) view.getLayoutParams();
        if (f3 == eVar.f10352b) {
            return;
        }
        eVar.f10352b = f3;
        l(view, f3);
    }

    void U(int i3, int i4, View view) {
        int i5;
        int iZ = this.f10329h.z();
        int iZ2 = this.f10330i.z();
        if (iZ == 1 || iZ2 == 1) {
            i5 = 1;
        } else {
            i5 = 2;
            if (iZ != 2 && iZ2 != 2) {
                i5 = 0;
            }
        }
        if (view != null && i4 == 0) {
            float f3 = ((e) view.getLayoutParams()).f10352b;
            if (f3 == 0.0f) {
                j(view);
            } else if (f3 == 1.0f) {
                k(view);
            }
        }
        if (i5 != this.f10333l) {
            this.f10333l = i5;
            List list = this.f10343v;
            if (list != null) {
                for (int size = list.size() - 1; size >= 0; size--) {
                    ((d) this.f10343v.get(size)).a(i5);
                }
            }
        }
    }

    public void a(d dVar) {
        if (dVar == null) {
            return;
        }
        if (this.f10343v == null) {
            this.f10343v = new ArrayList();
        }
        this.f10343v.add(dVar);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void addFocusables(ArrayList arrayList, int i3, int i4) {
        if (getDescendantFocusability() == 393216) {
            return;
        }
        int childCount = getChildCount();
        boolean z3 = false;
        for (int i5 = 0; i5 < childCount; i5++) {
            View childAt = getChildAt(i5);
            if (!D(childAt)) {
                this.f10320J.add(childAt);
            } else if (C(childAt)) {
                childAt.addFocusables(arrayList, i3, i4);
                z3 = true;
            }
        }
        if (!z3) {
            int size = this.f10320J.size();
            for (int i6 = 0; i6 < size; i6++) {
                View view = (View) this.f10320J.get(i6);
                if (view.getVisibility() == 0) {
                    view.addFocusables(arrayList, i3, i4);
                }
            }
        }
        this.f10320J.clear();
    }

    @Override // android.view.ViewGroup
    public void addView(View view, int i3, ViewGroup.LayoutParams layoutParams) {
        super.addView(view, i3, layoutParams);
        if (o() != null || D(view)) {
            V.f0(view, 4);
        } else {
            V.f0(view, 1);
        }
        if (f10309O) {
            return;
        }
        V.X(view, this.f10323b);
    }

    void b() {
        if (this.f10341t) {
            return;
        }
        long jUptimeMillis = SystemClock.uptimeMillis();
        MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, 0.0f, 0.0f, 0);
        int childCount = getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            getChildAt(i3).dispatchTouchEvent(motionEventObtain);
        }
        motionEventObtain.recycle();
        this.f10341t = true;
    }

    boolean c(View view, int i3) {
        return (t(view) & i3) == i3;
    }

    @Override // android.view.ViewGroup
    protected boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return (layoutParams instanceof e) && super.checkLayoutParams(layoutParams);
    }

    @Override // android.view.View
    public void computeScroll() {
        int childCount = getChildCount();
        float fMax = 0.0f;
        for (int i3 = 0; i3 < childCount; i3++) {
            fMax = Math.max(fMax, ((e) getChildAt(i3).getLayoutParams()).f10352b);
        }
        this.f10327f = fMax;
        boolean zM = this.f10329h.m(true);
        boolean zM2 = this.f10330i.m(true);
        if (zM || zM2) {
            V.R(this);
        }
    }

    public void d(int i3) {
        e(i3, true);
    }

    @Override // android.view.View
    public boolean dispatchGenericMotionEvent(MotionEvent motionEvent) {
        if ((motionEvent.getSource() & 2) == 0 || motionEvent.getAction() == 10 || this.f10327f <= 0.0f) {
            return super.dispatchGenericMotionEvent(motionEvent);
        }
        int childCount = getChildCount();
        if (childCount == 0) {
            return false;
        }
        float x3 = motionEvent.getX();
        float y3 = motionEvent.getY();
        for (int i3 = childCount - 1; i3 >= 0; i3--) {
            View childAt = getChildAt(i3);
            if (F(x3, y3, childAt) && !B(childAt) && m(motionEvent, childAt)) {
                return true;
            }
        }
        return false;
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View view, long j3) {
        int height = getHeight();
        boolean zB = B(view);
        int width = getWidth();
        int iSave = canvas.save();
        int i3 = 0;
        if (zB) {
            int childCount = getChildCount();
            int i4 = 0;
            for (int i5 = 0; i5 < childCount; i5++) {
                View childAt = getChildAt(i5);
                if (childAt != view && childAt.getVisibility() == 0 && x(childAt) && D(childAt) && childAt.getHeight() >= height) {
                    if (c(childAt, 3)) {
                        int right = childAt.getRight();
                        if (right > i4) {
                            i4 = right;
                        }
                    } else {
                        int left = childAt.getLeft();
                        if (left < width) {
                            width = left;
                        }
                    }
                }
            }
            canvas.clipRect(i4, 0, width, getHeight());
            i3 = i4;
        }
        boolean zDrawChild = super.drawChild(canvas, view, j3);
        canvas.restoreToCount(iSave);
        float f3 = this.f10327f;
        if (f3 > 0.0f && zB) {
            this.f10328g.setColor((this.f10326e & 16777215) | (((int) ((((-16777216) & r2) >>> 24) * f3)) << 24));
            canvas.drawRect(i3, 0.0f, width, getHeight(), this.f10328g);
        } else if (this.f10347z != null && c(view, 3)) {
            int intrinsicWidth = this.f10347z.getIntrinsicWidth();
            int right2 = view.getRight();
            float fMax = Math.max(0.0f, Math.min(right2 / this.f10329h.w(), 1.0f));
            this.f10347z.setBounds(right2, view.getTop(), intrinsicWidth + right2, view.getBottom());
            this.f10347z.setAlpha((int) (fMax * 255.0f));
            this.f10347z.draw(canvas);
        } else if (this.f10311A != null && c(view, 5)) {
            int intrinsicWidth2 = this.f10311A.getIntrinsicWidth();
            int left2 = view.getLeft();
            float fMax2 = Math.max(0.0f, Math.min((getWidth() - left2) / this.f10330i.w(), 1.0f));
            this.f10311A.setBounds(left2 - intrinsicWidth2, view.getTop(), left2, view.getBottom());
            this.f10311A.setAlpha((int) (fMax2 * 255.0f));
            this.f10311A.draw(canvas);
        }
        return zDrawChild;
    }

    public void e(int i3, boolean z3) {
        View viewN = n(i3);
        if (viewN != null) {
            g(viewN, z3);
            return;
        }
        throw new IllegalArgumentException("No drawer view found with gravity " + w(i3));
    }

    public void f(View view) {
        g(view, true);
    }

    public void g(View view, boolean z3) {
        if (!D(view)) {
            throw new IllegalArgumentException("View " + view + " is not a sliding drawer");
        }
        e eVar = (e) view.getLayoutParams();
        if (this.f10335n) {
            eVar.f10352b = 0.0f;
            eVar.f10354d = 0;
        } else if (z3) {
            eVar.f10354d |= 4;
            if (c(view, 3)) {
                this.f10329h.O(view, -view.getWidth(), view.getTop());
            } else {
                this.f10330i.O(view, getWidth(), view.getTop());
            }
        } else {
            H(view, 0.0f);
            U(eVar.f10351a, 0, view);
            view.setVisibility(4);
        }
        invalidate();
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new e(-1, -1);
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof e ? new e((e) layoutParams) : layoutParams instanceof ViewGroup.MarginLayoutParams ? new e((ViewGroup.MarginLayoutParams) layoutParams) : new e(layoutParams);
    }

    public float getDrawerElevation() {
        if (f10310P) {
            return this.f10324c;
        }
        return 0.0f;
    }

    public Drawable getStatusBarBackgroundDrawable() {
        return this.f10346y;
    }

    public void h() {
        i(false);
    }

    void i(boolean z3) {
        int childCount = getChildCount();
        boolean zO = false;
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = getChildAt(i3);
            e eVar = (e) childAt.getLayoutParams();
            if (D(childAt) && (!z3 || eVar.f10353c)) {
                zO |= c(childAt, 3) ? this.f10329h.O(childAt, -childAt.getWidth(), childAt.getTop()) : this.f10330i.O(childAt, getWidth(), childAt.getTop());
                eVar.f10353c = false;
            }
        }
        this.f10331j.p();
        this.f10332k.p();
        if (zO) {
            invalidate();
        }
    }

    void j(View view) {
        View rootView;
        e eVar = (e) view.getLayoutParams();
        if ((eVar.f10354d & 1) == 1) {
            eVar.f10354d = 0;
            List list = this.f10343v;
            if (list != null) {
                for (int size = list.size() - 1; size >= 0; size--) {
                    ((d) this.f10343v.get(size)).d(view);
                }
            }
            T(view, false);
            if (!hasWindowFocus() || (rootView = getRootView()) == null) {
                return;
            }
            rootView.sendAccessibilityEvent(32);
        }
    }

    void k(View view) {
        e eVar = (e) view.getLayoutParams();
        if ((eVar.f10354d & 1) == 0) {
            eVar.f10354d = 1;
            List list = this.f10343v;
            if (list != null) {
                for (int size = list.size() - 1; size >= 0; size--) {
                    ((d) this.f10343v.get(size)).c(view);
                }
            }
            T(view, true);
            if (hasWindowFocus()) {
                sendAccessibilityEvent(32);
            }
        }
    }

    void l(View view, float f3) {
        List list = this.f10343v;
        if (list != null) {
            for (int size = list.size() - 1; size >= 0; size--) {
                ((d) this.f10343v.get(size)).b(view, f3);
            }
        }
    }

    View n(int i3) {
        int iA = AbstractC0281s.a(i3, V.s(this)) & 7;
        int childCount = getChildCount();
        for (int i4 = 0; i4 < childCount; i4++) {
            View childAt = getChildAt(i4);
            if ((t(childAt) & 7) == iA) {
                return childAt;
            }
        }
        return null;
    }

    View o() {
        int childCount = getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = getChildAt(i3);
            if ((((e) childAt.getLayoutParams()).f10354d & 1) == 1) {
                return childAt;
            }
        }
        return null;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f10335n = true;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f10335n = true;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (!this.f10315E || this.f10346y == null) {
            return;
        }
        Object obj = this.f10314D;
        int systemWindowInsetTop = obj != null ? ((WindowInsets) obj).getSystemWindowInsetTop() : 0;
        if (systemWindowInsetTop > 0) {
            this.f10346y.setBounds(0, 0, getWidth(), systemWindowInsetTop);
            this.f10346y.draw(canvas);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0031  */
    @Override // android.view.ViewGroup
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onInterceptTouchEvent(android.view.MotionEvent r7) {
        /*
            r6 = this;
            int r0 = r7.getActionMasked()
            w.c r1 = r6.f10329h
            boolean r1 = r1.N(r7)
            w.c r2 = r6.f10330i
            boolean r2 = r2.N(r7)
            r1 = r1 | r2
            r2 = 1
            r3 = 0
            if (r0 == 0) goto L3a
            if (r0 == r2) goto L31
            r7 = 2
            r4 = 3
            if (r0 == r7) goto L1e
            if (r0 == r4) goto L31
            goto L38
        L1e:
            w.c r7 = r6.f10329h
            boolean r7 = r7.d(r4)
            if (r7 == 0) goto L38
            x.a$g r7 = r6.f10331j
            r7.p()
            x.a$g r7 = r6.f10332k
            r7.p()
            goto L38
        L31:
            r6.i(r2)
            r6.f10340s = r3
            r6.f10341t = r3
        L38:
            r7 = r3
            goto L64
        L3a:
            float r0 = r7.getX()
            float r7 = r7.getY()
            r6.f10344w = r0
            r6.f10345x = r7
            float r4 = r6.f10327f
            r5 = 0
            int r4 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r4 <= 0) goto L5f
            w.c r4 = r6.f10329h
            int r0 = (int) r0
            int r7 = (int) r7
            android.view.View r7 = r4.t(r0, r7)
            if (r7 == 0) goto L5f
            boolean r7 = r6.B(r7)
            if (r7 == 0) goto L5f
            r7 = r2
            goto L60
        L5f:
            r7 = r3
        L60:
            r6.f10340s = r3
            r6.f10341t = r3
        L64:
            if (r1 != 0) goto L74
            if (r7 != 0) goto L74
            boolean r7 = r6.y()
            if (r7 != 0) goto L74
            boolean r7 = r6.f10341t
            if (r7 == 0) goto L73
            goto L74
        L73:
            r2 = r3
        L74:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: x.AbstractC0715a.onInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyDown(int i3, KeyEvent keyEvent) {
        if (i3 != 4 || !z()) {
            return super.onKeyDown(i3, keyEvent);
        }
        keyEvent.startTracking();
        return true;
    }

    @Override // android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyUp(int i3, KeyEvent keyEvent) {
        if (i3 != 4) {
            return super.onKeyUp(i3, keyEvent);
        }
        View viewP = p();
        if (viewP != null && r(viewP) == 0) {
            h();
        }
        return viewP != null;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        float f3;
        int i7;
        boolean z4 = true;
        this.f10334m = true;
        int i8 = i5 - i3;
        int childCount = getChildCount();
        int i9 = 0;
        while (i9 < childCount) {
            View childAt = getChildAt(i9);
            if (childAt.getVisibility() != 8) {
                e eVar = (e) childAt.getLayoutParams();
                if (B(childAt)) {
                    int i10 = ((ViewGroup.MarginLayoutParams) eVar).leftMargin;
                    childAt.layout(i10, ((ViewGroup.MarginLayoutParams) eVar).topMargin, childAt.getMeasuredWidth() + i10, ((ViewGroup.MarginLayoutParams) eVar).topMargin + childAt.getMeasuredHeight());
                } else {
                    int measuredWidth = childAt.getMeasuredWidth();
                    int measuredHeight = childAt.getMeasuredHeight();
                    if (c(childAt, 3)) {
                        float f4 = measuredWidth;
                        i7 = (-measuredWidth) + ((int) (eVar.f10352b * f4));
                        f3 = (measuredWidth + i7) / f4;
                    } else {
                        float f5 = measuredWidth;
                        f3 = (i8 - r11) / f5;
                        i7 = i8 - ((int) (eVar.f10352b * f5));
                    }
                    boolean z5 = f3 != eVar.f10352b ? z4 : false;
                    int i11 = eVar.f10351a & 112;
                    if (i11 == 16) {
                        int i12 = i6 - i4;
                        int i13 = (i12 - measuredHeight) / 2;
                        int i14 = ((ViewGroup.MarginLayoutParams) eVar).topMargin;
                        if (i13 < i14) {
                            i13 = i14;
                        } else {
                            int i15 = i13 + measuredHeight;
                            int i16 = ((ViewGroup.MarginLayoutParams) eVar).bottomMargin;
                            if (i15 > i12 - i16) {
                                i13 = (i12 - i16) - measuredHeight;
                            }
                        }
                        childAt.layout(i7, i13, measuredWidth + i7, measuredHeight + i13);
                    } else if (i11 != 80) {
                        int i17 = ((ViewGroup.MarginLayoutParams) eVar).topMargin;
                        childAt.layout(i7, i17, measuredWidth + i7, measuredHeight + i17);
                    } else {
                        int i18 = i6 - i4;
                        childAt.layout(i7, (i18 - ((ViewGroup.MarginLayoutParams) eVar).bottomMargin) - childAt.getMeasuredHeight(), measuredWidth + i7, i18 - ((ViewGroup.MarginLayoutParams) eVar).bottomMargin);
                    }
                    if (z5) {
                        S(childAt, f3);
                    }
                    int i19 = eVar.f10352b > 0.0f ? 0 : 4;
                    if (childAt.getVisibility() != i19) {
                        childAt.setVisibility(i19);
                    }
                }
            }
            i9++;
            z4 = true;
        }
        this.f10334m = false;
        this.f10335n = false;
    }

    @Override // android.view.View
    protected void onMeasure(int i3, int i4) {
        int mode = View.MeasureSpec.getMode(i3);
        int mode2 = View.MeasureSpec.getMode(i4);
        int size = View.MeasureSpec.getSize(i3);
        int size2 = View.MeasureSpec.getSize(i4);
        if (mode != 1073741824 || mode2 != 1073741824) {
            if (!isInEditMode()) {
                throw new IllegalArgumentException("DrawerLayout must be measured with MeasureSpec.EXACTLY.");
            }
            if (mode != Integer.MIN_VALUE && mode == 0) {
                size = 300;
            }
            if (mode2 != Integer.MIN_VALUE && mode2 == 0) {
                size2 = 300;
            }
        }
        setMeasuredDimension(size, size2);
        boolean z3 = this.f10314D != null && V.q(this);
        int iS = V.s(this);
        int childCount = getChildCount();
        boolean z4 = false;
        boolean z5 = false;
        for (int i5 = 0; i5 < childCount; i5++) {
            View childAt = getChildAt(i5);
            if (childAt.getVisibility() != 8) {
                e eVar = (e) childAt.getLayoutParams();
                if (z3) {
                    int iA = AbstractC0281s.a(eVar.f10351a, iS);
                    if (V.q(childAt)) {
                        WindowInsets windowInsetsReplaceSystemWindowInsets = (WindowInsets) this.f10314D;
                        if (iA == 3) {
                            windowInsetsReplaceSystemWindowInsets = windowInsetsReplaceSystemWindowInsets.replaceSystemWindowInsets(windowInsetsReplaceSystemWindowInsets.getSystemWindowInsetLeft(), windowInsetsReplaceSystemWindowInsets.getSystemWindowInsetTop(), 0, windowInsetsReplaceSystemWindowInsets.getSystemWindowInsetBottom());
                        } else if (iA == 5) {
                            windowInsetsReplaceSystemWindowInsets = windowInsetsReplaceSystemWindowInsets.replaceSystemWindowInsets(0, windowInsetsReplaceSystemWindowInsets.getSystemWindowInsetTop(), windowInsetsReplaceSystemWindowInsets.getSystemWindowInsetRight(), windowInsetsReplaceSystemWindowInsets.getSystemWindowInsetBottom());
                        }
                        childAt.dispatchApplyWindowInsets(windowInsetsReplaceSystemWindowInsets);
                    } else {
                        WindowInsets windowInsetsReplaceSystemWindowInsets2 = (WindowInsets) this.f10314D;
                        if (iA == 3) {
                            windowInsetsReplaceSystemWindowInsets2 = windowInsetsReplaceSystemWindowInsets2.replaceSystemWindowInsets(windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetLeft(), windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetTop(), 0, windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetBottom());
                        } else if (iA == 5) {
                            windowInsetsReplaceSystemWindowInsets2 = windowInsetsReplaceSystemWindowInsets2.replaceSystemWindowInsets(0, windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetTop(), windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetRight(), windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetBottom());
                        }
                        ((ViewGroup.MarginLayoutParams) eVar).leftMargin = windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetLeft();
                        ((ViewGroup.MarginLayoutParams) eVar).topMargin = windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetTop();
                        ((ViewGroup.MarginLayoutParams) eVar).rightMargin = windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetRight();
                        ((ViewGroup.MarginLayoutParams) eVar).bottomMargin = windowInsetsReplaceSystemWindowInsets2.getSystemWindowInsetBottom();
                    }
                }
                if (B(childAt)) {
                    childAt.measure(View.MeasureSpec.makeMeasureSpec((size - ((ViewGroup.MarginLayoutParams) eVar).leftMargin) - ((ViewGroup.MarginLayoutParams) eVar).rightMargin, 1073741824), View.MeasureSpec.makeMeasureSpec((size2 - ((ViewGroup.MarginLayoutParams) eVar).topMargin) - ((ViewGroup.MarginLayoutParams) eVar).bottomMargin, 1073741824));
                } else {
                    if (!D(childAt)) {
                        throw new IllegalStateException("Child " + childAt + " at index " + i5 + " does not have a valid layout_gravity - must be Gravity.LEFT, Gravity.RIGHT or Gravity.NO_GRAVITY");
                    }
                    if (f10310P) {
                        float fO = V.o(childAt);
                        float f3 = this.f10324c;
                        if (fO != f3) {
                            V.e0(childAt, f3);
                        }
                    }
                    int iT = t(childAt) & 7;
                    boolean z6 = iT == 3;
                    if ((z6 && z4) || (!z6 && z5)) {
                        throw new IllegalStateException("Child drawer has absolute gravity " + w(iT) + " but this DrawerLayout already has a drawer view along that edge");
                    }
                    if (z6) {
                        z4 = true;
                    } else {
                        z5 = true;
                    }
                    childAt.measure(ViewGroup.getChildMeasureSpec(i3, this.f10325d + ((ViewGroup.MarginLayoutParams) eVar).leftMargin + ((ViewGroup.MarginLayoutParams) eVar).rightMargin, ((ViewGroup.MarginLayoutParams) eVar).width), ViewGroup.getChildMeasureSpec(i4, ((ViewGroup.MarginLayoutParams) eVar).topMargin + ((ViewGroup.MarginLayoutParams) eVar).bottomMargin, ((ViewGroup.MarginLayoutParams) eVar).height));
                }
            }
        }
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable parcelable) {
        View viewN;
        if (!(parcelable instanceof f)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        f fVar = (f) parcelable;
        super.onRestoreInstanceState(fVar.a());
        int i3 = fVar.f10355c;
        if (i3 != 0 && (viewN = n(i3)) != null) {
            K(viewN);
        }
        int i4 = fVar.f10356d;
        if (i4 != 3) {
            R(i4, 3);
        }
        int i5 = fVar.f10357e;
        if (i5 != 3) {
            R(i5, 5);
        }
        int i6 = fVar.f10358f;
        if (i6 != 3) {
            R(i6, 8388611);
        }
        int i7 = fVar.f10359g;
        if (i7 != 3) {
            R(i7, 8388613);
        }
    }

    @Override // android.view.View
    public void onRtlPropertiesChanged(int i3) {
        P();
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        f fVar = new f(super.onSaveInstanceState());
        int childCount = getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            e eVar = (e) getChildAt(i3).getLayoutParams();
            int i4 = eVar.f10354d;
            boolean z3 = i4 == 1;
            boolean z4 = i4 == 2;
            if (z3 || z4) {
                fVar.f10355c = eVar.f10351a;
                break;
            }
        }
        fVar.f10356d = this.f10336o;
        fVar.f10357e = this.f10337p;
        fVar.f10358f = this.f10338q;
        fVar.f10359g = this.f10339r;
        return fVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x005f  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r7) {
        /*
            r6 = this;
            w.c r0 = r6.f10329h
            r0.E(r7)
            w.c r0 = r6.f10330i
            r0.E(r7)
            int r0 = r7.getAction()
            r0 = r0 & 255(0xff, float:3.57E-43)
            r1 = 0
            r2 = 1
            if (r0 == 0) goto L66
            if (r0 == r2) goto L22
            r7 = 3
            if (r0 == r7) goto L1a
            goto L76
        L1a:
            r6.i(r2)
            r6.f10340s = r1
            r6.f10341t = r1
            goto L76
        L22:
            float r0 = r7.getX()
            float r7 = r7.getY()
            w.c r3 = r6.f10329h
            int r4 = (int) r0
            int r5 = (int) r7
            android.view.View r3 = r3.t(r4, r5)
            if (r3 == 0) goto L5f
            boolean r3 = r6.B(r3)
            if (r3 == 0) goto L5f
            float r3 = r6.f10344w
            float r0 = r0 - r3
            float r3 = r6.f10345x
            float r7 = r7 - r3
            w.c r3 = r6.f10329h
            int r3 = r3.y()
            float r0 = r0 * r0
            float r7 = r7 * r7
            float r0 = r0 + r7
            int r3 = r3 * r3
            float r7 = (float) r3
            int r7 = (r0 > r7 ? 1 : (r0 == r7 ? 0 : -1))
            if (r7 >= 0) goto L5f
            android.view.View r7 = r6.o()
            if (r7 == 0) goto L5f
            int r7 = r6.r(r7)
            r0 = 2
            if (r7 != r0) goto L5d
            goto L5f
        L5d:
            r7 = r1
            goto L60
        L5f:
            r7 = r2
        L60:
            r6.i(r7)
            r6.f10340s = r1
            goto L76
        L66:
            float r0 = r7.getX()
            float r7 = r7.getY()
            r6.f10344w = r0
            r6.f10345x = r7
            r6.f10340s = r1
            r6.f10341t = r1
        L76:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: x.AbstractC0715a.onTouchEvent(android.view.MotionEvent):boolean");
    }

    View p() {
        int childCount = getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = getChildAt(i3);
            if (D(childAt) && E(childAt)) {
                return childAt;
            }
        }
        return null;
    }

    public int q(int i3) {
        int iS = V.s(this);
        if (i3 == 3) {
            int i4 = this.f10336o;
            if (i4 != 3) {
                return i4;
            }
            int i5 = iS == 0 ? this.f10338q : this.f10339r;
            if (i5 != 3) {
                return i5;
            }
            return 0;
        }
        if (i3 == 5) {
            int i6 = this.f10337p;
            if (i6 != 3) {
                return i6;
            }
            int i7 = iS == 0 ? this.f10339r : this.f10338q;
            if (i7 != 3) {
                return i7;
            }
            return 0;
        }
        if (i3 == 8388611) {
            int i8 = this.f10338q;
            if (i8 != 3) {
                return i8;
            }
            int i9 = iS == 0 ? this.f10336o : this.f10337p;
            if (i9 != 3) {
                return i9;
            }
            return 0;
        }
        if (i3 != 8388613) {
            return 0;
        }
        int i10 = this.f10339r;
        if (i10 != 3) {
            return i10;
        }
        int i11 = iS == 0 ? this.f10337p : this.f10336o;
        if (i11 != 3) {
            return i11;
        }
        return 0;
    }

    public int r(View view) {
        if (D(view)) {
            return q(((e) view.getLayoutParams()).f10351a);
        }
        throw new IllegalArgumentException("View " + view + " is not a drawer");
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean z3) {
        super.requestDisallowInterceptTouchEvent(z3);
        this.f10340s = z3;
        if (z3) {
            i(true);
        }
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (this.f10334m) {
            return;
        }
        super.requestLayout();
    }

    public CharSequence s(int i3) {
        int iA = AbstractC0281s.a(i3, V.s(this));
        if (iA == 3) {
            return this.f10312B;
        }
        if (iA == 5) {
            return this.f10313C;
        }
        return null;
    }

    public void setDrawerElevation(float f3) {
        this.f10324c = f3;
        for (int i3 = 0; i3 < getChildCount(); i3++) {
            View childAt = getChildAt(i3);
            if (D(childAt)) {
                V.e0(childAt, this.f10324c);
            }
        }
    }

    @Deprecated
    public void setDrawerListener(d dVar) {
        d dVar2 = this.f10342u;
        if (dVar2 != null) {
            M(dVar2);
        }
        if (dVar != null) {
            a(dVar);
        }
        this.f10342u = dVar;
    }

    public void setDrawerLockMode(int i3) {
        R(i3, 3);
        R(i3, 5);
    }

    public void setScrimColor(int i3) {
        this.f10326e = i3;
        invalidate();
    }

    public void setStatusBarBackground(Drawable drawable) {
        this.f10346y = drawable;
        invalidate();
    }

    public void setStatusBarBackgroundColor(int i3) {
        this.f10346y = new ColorDrawable(i3);
        invalidate();
    }

    int t(View view) {
        return AbstractC0281s.a(((e) view.getLayoutParams()).f10351a, V.s(this));
    }

    float u(View view) {
        return ((e) view.getLayoutParams()).f10352b;
    }

    public AbstractC0715a(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new e(getContext(), attributeSet);
    }

    public AbstractC0715a(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        this.f10323b = new c();
        this.f10326e = -1728053248;
        this.f10328g = new Paint();
        this.f10335n = true;
        this.f10336o = 3;
        this.f10337p = 3;
        this.f10338q = 3;
        this.f10339r = 3;
        this.f10316F = null;
        this.f10317G = null;
        this.f10318H = null;
        this.f10319I = null;
        setDescendantFocusability(262144);
        float f3 = getResources().getDisplayMetrics().density;
        this.f10325d = (int) ((64.0f * f3) + 0.5f);
        float f4 = 400.0f * f3;
        g gVar = new g(3);
        this.f10331j = gVar;
        g gVar2 = new g(5);
        this.f10332k = gVar2;
        C0711c c0711cN = C0711c.n(this, 1.0f, gVar);
        this.f10329h = c0711cN;
        c0711cN.K(1);
        c0711cN.L(f4);
        gVar.q(c0711cN);
        C0711c c0711cN2 = C0711c.n(this, 1.0f, gVar2);
        this.f10330i = c0711cN2;
        c0711cN2.K(2);
        c0711cN2.L(f4);
        gVar2.q(c0711cN2);
        setFocusableInTouchMode(true);
        V.f0(this, 1);
        V.X(this, new b());
        setMotionEventSplittingEnabled(false);
        if (V.q(this)) {
            setOnApplyWindowInsetsListener(new ViewOnApplyWindowInsetsListenerC0156a());
            setSystemUiVisibility(1280);
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(f10307M);
            try {
                this.f10346y = typedArrayObtainStyledAttributes.getDrawable(0);
            } finally {
                typedArrayObtainStyledAttributes.recycle();
            }
        }
        this.f10324c = f3 * 10.0f;
        this.f10320J = new ArrayList();
    }

    public void setStatusBarBackground(int i3) {
        this.f10346y = i3 != 0 ? androidx.core.content.a.d(getContext(), i3) : null;
        invalidate();
    }

    /* JADX INFO: renamed from: x.a$e */
    public static class e extends ViewGroup.MarginLayoutParams {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public int f10351a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        float f10352b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        boolean f10353c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        int f10354d;

        public e(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.f10351a = 0;
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, AbstractC0715a.f10308N);
            this.f10351a = typedArrayObtainStyledAttributes.getInt(0, 0);
            typedArrayObtainStyledAttributes.recycle();
        }

        public e(int i3, int i4) {
            super(i3, i4);
            this.f10351a = 0;
        }

        public e(e eVar) {
            super((ViewGroup.MarginLayoutParams) eVar);
            this.f10351a = 0;
            this.f10351a = eVar.f10351a;
        }

        public e(ViewGroup.LayoutParams layoutParams) {
            super(layoutParams);
            this.f10351a = 0;
        }

        public e(ViewGroup.MarginLayoutParams marginLayoutParams) {
            super(marginLayoutParams);
            this.f10351a = 0;
        }
    }

    /* JADX INFO: renamed from: x.a$f */
    protected static class f extends AbstractC0704a {
        public static final Parcelable.Creator<f> CREATOR = new C0157a();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        int f10355c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        int f10356d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        int f10357e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        int f10358f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        int f10359g;

        /* JADX INFO: renamed from: x.a$f$a, reason: collision with other inner class name */
        static class C0157a implements Parcelable.ClassLoaderCreator {
            C0157a() {
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
            public f createFromParcel(Parcel parcel) {
                return new f(parcel, null);
            }

            @Override // android.os.Parcelable.ClassLoaderCreator
            /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
            public f createFromParcel(Parcel parcel, ClassLoader classLoader) {
                return new f(parcel, classLoader);
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
            public f[] newArray(int i3) {
                return new f[i3];
            }
        }

        public f(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.f10355c = 0;
            this.f10355c = parcel.readInt();
            this.f10356d = parcel.readInt();
            this.f10357e = parcel.readInt();
            this.f10358f = parcel.readInt();
            this.f10359g = parcel.readInt();
        }

        @Override // v.AbstractC0704a, android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i3) {
            super.writeToParcel(parcel, i3);
            parcel.writeInt(this.f10355c);
            parcel.writeInt(this.f10356d);
            parcel.writeInt(this.f10357e);
            parcel.writeInt(this.f10358f);
            parcel.writeInt(this.f10359g);
        }

        public f(Parcelable parcelable) {
            super(parcelable);
            this.f10355c = 0;
        }
    }
}
