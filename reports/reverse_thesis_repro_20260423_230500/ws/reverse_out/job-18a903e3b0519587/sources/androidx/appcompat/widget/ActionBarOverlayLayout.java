package androidx.appcompat.widget;

import android.R;
import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewPropertyAnimator;
import android.view.Window;
import android.view.WindowInsets;
import android.widget.OverScroller;
import androidx.appcompat.view.menu.j;
import androidx.core.view.C0271j0;
import d.AbstractC0502a;

/* JADX INFO: loaded from: classes.dex */
public class ActionBarOverlayLayout extends ViewGroup implements I, androidx.core.view.B, androidx.core.view.C {

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    static final int[] f3644H = {AbstractC0502a.f8790b, R.attr.windowContentOverlay};

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private static final C0271j0 f3645I = new C0271j0.b().c(androidx.core.graphics.b.b(0, 1, 0, 1)).a();

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private static final Rect f3646J = new Rect();

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private OverScroller f3647A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    ViewPropertyAnimator f3648B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    final AnimatorListenerAdapter f3649C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final Runnable f3650D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private final Runnable f3651E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private final androidx.core.view.D f3652F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private final f f3653G;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f3654b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f3655c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private ContentFrameLayout f3656d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    ActionBarContainer f3657e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private J f3658f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Drawable f3659g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f3660h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f3661i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f3662j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    boolean f3663k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f3664l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f3665m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final Rect f3666n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final Rect f3667o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final Rect f3668p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final Rect f3669q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final Rect f3670r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final Rect f3671s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final Rect f3672t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final Rect f3673u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private C0271j0 f3674v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private C0271j0 f3675w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private C0271j0 f3676x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private C0271j0 f3677y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private d f3678z;

    class a extends AnimatorListenerAdapter {
        a() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animator) {
            ActionBarOverlayLayout actionBarOverlayLayout = ActionBarOverlayLayout.this;
            actionBarOverlayLayout.f3648B = null;
            actionBarOverlayLayout.f3663k = false;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            ActionBarOverlayLayout actionBarOverlayLayout = ActionBarOverlayLayout.this;
            actionBarOverlayLayout.f3648B = null;
            actionBarOverlayLayout.f3663k = false;
        }
    }

    class b implements Runnable {
        b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            ActionBarOverlayLayout.this.v();
            ActionBarOverlayLayout actionBarOverlayLayout = ActionBarOverlayLayout.this;
            actionBarOverlayLayout.f3648B = actionBarOverlayLayout.f3657e.animate().translationY(0.0f).setListener(ActionBarOverlayLayout.this.f3649C);
        }
    }

    class c implements Runnable {
        c() {
        }

        @Override // java.lang.Runnable
        public void run() {
            ActionBarOverlayLayout.this.v();
            ActionBarOverlayLayout actionBarOverlayLayout = ActionBarOverlayLayout.this;
            actionBarOverlayLayout.f3648B = actionBarOverlayLayout.f3657e.animate().translationY(-ActionBarOverlayLayout.this.f3657e.getHeight()).setListener(ActionBarOverlayLayout.this.f3649C);
        }
    }

    public interface d {
        void a();

        void b();

        void c(int i3);

        void d();

        void e(boolean z3);

        void f();
    }

    public static class e extends ViewGroup.MarginLayoutParams {
        public e(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
        }

        public e(int i3, int i4) {
            super(i3, i4);
        }

        public e(ViewGroup.LayoutParams layoutParams) {
            super(layoutParams);
        }
    }

    private static final class f extends View {
        f(Context context) {
            super(context);
            setWillNotDraw(true);
        }

        @Override // android.view.View
        public int getWindowSystemUiVisibility() {
            return 0;
        }
    }

    public ActionBarOverlayLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f3655c = 0;
        this.f3666n = new Rect();
        this.f3667o = new Rect();
        this.f3668p = new Rect();
        this.f3669q = new Rect();
        this.f3670r = new Rect();
        this.f3671s = new Rect();
        this.f3672t = new Rect();
        this.f3673u = new Rect();
        C0271j0 c0271j0 = C0271j0.f4470b;
        this.f3674v = c0271j0;
        this.f3675w = c0271j0;
        this.f3676x = c0271j0;
        this.f3677y = c0271j0;
        this.f3649C = new a();
        this.f3650D = new b();
        this.f3651E = new c();
        w(context);
        this.f3652F = new androidx.core.view.D(this);
        f fVar = new f(context);
        this.f3653G = fVar;
        addView(fVar);
    }

    private void B() {
        v();
        this.f3650D.run();
    }

    private boolean C(float f3) {
        this.f3647A.fling(0, 0, 0, (int) f3, 0, 0, Integer.MIN_VALUE, Integer.MAX_VALUE);
        return this.f3647A.getFinalY() > this.f3657e.getHeight();
    }

    private void p() {
        v();
        this.f3651E.run();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean q(android.view.View r3, android.graphics.Rect r4, boolean r5, boolean r6, boolean r7, boolean r8) {
        /*
            r2 = this;
            android.view.ViewGroup$LayoutParams r3 = r3.getLayoutParams()
            androidx.appcompat.widget.ActionBarOverlayLayout$e r3 = (androidx.appcompat.widget.ActionBarOverlayLayout.e) r3
            r0 = 1
            if (r5 == 0) goto L13
            int r5 = r3.leftMargin
            int r1 = r4.left
            if (r5 == r1) goto L13
            r3.leftMargin = r1
            r5 = r0
            goto L14
        L13:
            r5 = 0
        L14:
            if (r6 == 0) goto L1f
            int r6 = r3.topMargin
            int r1 = r4.top
            if (r6 == r1) goto L1f
            r3.topMargin = r1
            r5 = r0
        L1f:
            if (r8 == 0) goto L2a
            int r6 = r3.rightMargin
            int r8 = r4.right
            if (r6 == r8) goto L2a
            r3.rightMargin = r8
            r5 = r0
        L2a:
            if (r7 == 0) goto L35
            int r6 = r3.bottomMargin
            int r4 = r4.bottom
            if (r6 == r4) goto L35
            r3.bottomMargin = r4
            goto L36
        L35:
            r0 = r5
        L36:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActionBarOverlayLayout.q(android.view.View, android.graphics.Rect, boolean, boolean, boolean, boolean):boolean");
    }

    private boolean r() {
        androidx.core.view.V.d(this.f3653G, f3645I, this.f3669q);
        return !this.f3669q.equals(f3646J);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private J u(View view) {
        if (view instanceof J) {
            return (J) view;
        }
        if (view instanceof Toolbar) {
            return ((Toolbar) view).getWrapper();
        }
        throw new IllegalStateException("Can't make a decor toolbar out of " + view.getClass().getSimpleName());
    }

    private void w(Context context) {
        TypedArray typedArrayObtainStyledAttributes = getContext().getTheme().obtainStyledAttributes(f3644H);
        this.f3654b = typedArrayObtainStyledAttributes.getDimensionPixelSize(0, 0);
        Drawable drawable = typedArrayObtainStyledAttributes.getDrawable(1);
        this.f3659g = drawable;
        setWillNotDraw(drawable == null);
        typedArrayObtainStyledAttributes.recycle();
        this.f3647A = new OverScroller(context);
    }

    private void y() {
        v();
        postDelayed(this.f3651E, 600L);
    }

    private void z() {
        v();
        postDelayed(this.f3650D, 600L);
    }

    void A() {
        if (this.f3656d == null) {
            this.f3656d = (ContentFrameLayout) findViewById(d.f.f8885b);
            this.f3657e = (ActionBarContainer) findViewById(d.f.f8886c);
            this.f3658f = u(findViewById(d.f.f8884a));
        }
    }

    @Override // androidx.appcompat.widget.I
    public void a(Menu menu, j.a aVar) {
        A();
        this.f3658f.a(menu, aVar);
    }

    @Override // androidx.appcompat.widget.I
    public boolean b() {
        A();
        return this.f3658f.b();
    }

    @Override // androidx.core.view.B
    public void c(View view, View view2, int i3, int i4) {
        if (i4 == 0) {
            onNestedScrollAccepted(view, view2, i3);
        }
    }

    @Override // android.view.ViewGroup
    protected boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof e;
    }

    @Override // androidx.appcompat.widget.I
    public void d() {
        A();
        this.f3658f.d();
    }

    @Override // android.view.View
    public void draw(Canvas canvas) {
        super.draw(canvas);
        if (this.f3659g != null) {
            int bottom = this.f3657e.getVisibility() == 0 ? (int) (this.f3657e.getBottom() + this.f3657e.getTranslationY() + 0.5f) : 0;
            this.f3659g.setBounds(0, bottom, getWidth(), this.f3659g.getIntrinsicHeight() + bottom);
            this.f3659g.draw(canvas);
        }
    }

    @Override // androidx.appcompat.widget.I
    public boolean e() {
        A();
        return this.f3658f.e();
    }

    @Override // androidx.appcompat.widget.I
    public boolean f() {
        A();
        return this.f3658f.f();
    }

    @Override // android.view.View
    protected boolean fitSystemWindows(Rect rect) {
        return super.fitSystemWindows(rect);
    }

    @Override // androidx.appcompat.widget.I
    public boolean g() {
        A();
        return this.f3658f.g();
    }

    public int getActionBarHideOffset() {
        ActionBarContainer actionBarContainer = this.f3657e;
        if (actionBarContainer != null) {
            return -((int) actionBarContainer.getTranslationY());
        }
        return 0;
    }

    @Override // android.view.ViewGroup
    public int getNestedScrollAxes() {
        return this.f3652F.a();
    }

    public CharSequence getTitle() {
        A();
        return this.f3658f.getTitle();
    }

    @Override // androidx.appcompat.widget.I
    public boolean h() {
        A();
        return this.f3658f.h();
    }

    @Override // androidx.core.view.B
    public void i(View view, int i3) {
        if (i3 == 0) {
            onStopNestedScroll(view);
        }
    }

    @Override // androidx.core.view.B
    public void j(View view, int i3, int i4, int[] iArr, int i5) {
        if (i5 == 0) {
            onNestedPreScroll(view, i3, i4, iArr);
        }
    }

    @Override // androidx.appcompat.widget.I
    public void k(int i3) {
        A();
        if (i3 == 2) {
            this.f3658f.s();
        } else if (i3 == 5) {
            this.f3658f.t();
        } else {
            if (i3 != 109) {
                return;
            }
            setOverlayMode(true);
        }
    }

    @Override // androidx.appcompat.widget.I
    public void l() {
        A();
        this.f3658f.i();
    }

    @Override // androidx.core.view.C
    public void m(View view, int i3, int i4, int i5, int i6, int i7, int[] iArr) {
        n(view, i3, i4, i5, i6, i7);
    }

    @Override // androidx.core.view.B
    public void n(View view, int i3, int i4, int i5, int i6, int i7) {
        if (i7 == 0) {
            onNestedScroll(view, i3, i4, i5, i6);
        }
    }

    @Override // androidx.core.view.B
    public boolean o(View view, View view2, int i3, int i4) {
        return i4 == 0 && onStartNestedScroll(view, view2, i3);
    }

    @Override // android.view.View
    public WindowInsets onApplyWindowInsets(WindowInsets windowInsets) {
        A();
        C0271j0 c0271j0W = C0271j0.w(windowInsets, this);
        boolean zQ = q(this.f3657e, new Rect(c0271j0W.i(), c0271j0W.k(), c0271j0W.j(), c0271j0W.h()), true, true, false, true);
        androidx.core.view.V.d(this, c0271j0W, this.f3666n);
        Rect rect = this.f3666n;
        C0271j0 c0271j0L = c0271j0W.l(rect.left, rect.top, rect.right, rect.bottom);
        this.f3674v = c0271j0L;
        boolean z3 = true;
        if (!this.f3675w.equals(c0271j0L)) {
            this.f3675w = this.f3674v;
            zQ = true;
        }
        if (this.f3667o.equals(this.f3666n)) {
            z3 = zQ;
        } else {
            this.f3667o.set(this.f3666n);
        }
        if (z3) {
            requestLayout();
        }
        return c0271j0W.a().c().b().u();
    }

    @Override // android.view.View
    protected void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        w(getContext());
        androidx.core.view.V.U(this);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        v();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        int childCount = getChildCount();
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        for (int i7 = 0; i7 < childCount; i7++) {
            View childAt = getChildAt(i7);
            if (childAt.getVisibility() != 8) {
                e eVar = (e) childAt.getLayoutParams();
                int measuredWidth = childAt.getMeasuredWidth();
                int measuredHeight = childAt.getMeasuredHeight();
                int i8 = ((ViewGroup.MarginLayoutParams) eVar).leftMargin + paddingLeft;
                int i9 = ((ViewGroup.MarginLayoutParams) eVar).topMargin + paddingTop;
                childAt.layout(i8, i9, measuredWidth + i8, measuredHeight + i9);
            }
        }
    }

    @Override // android.view.View
    protected void onMeasure(int i3, int i4) {
        int measuredHeight;
        A();
        measureChildWithMargins(this.f3657e, i3, 0, i4, 0);
        e eVar = (e) this.f3657e.getLayoutParams();
        int iMax = Math.max(0, this.f3657e.getMeasuredWidth() + ((ViewGroup.MarginLayoutParams) eVar).leftMargin + ((ViewGroup.MarginLayoutParams) eVar).rightMargin);
        int iMax2 = Math.max(0, this.f3657e.getMeasuredHeight() + ((ViewGroup.MarginLayoutParams) eVar).topMargin + ((ViewGroup.MarginLayoutParams) eVar).bottomMargin);
        int iCombineMeasuredStates = View.combineMeasuredStates(0, this.f3657e.getMeasuredState());
        boolean z3 = (androidx.core.view.V.B(this) & 256) != 0;
        if (z3) {
            measuredHeight = this.f3654b;
            if (this.f3661i && this.f3657e.getTabContainer() != null) {
                measuredHeight += this.f3654b;
            }
        } else {
            measuredHeight = this.f3657e.getVisibility() != 8 ? this.f3657e.getMeasuredHeight() : 0;
        }
        this.f3668p.set(this.f3666n);
        this.f3676x = this.f3674v;
        if (this.f3660h || z3 || !r()) {
            this.f3676x = new C0271j0.b(this.f3676x).c(androidx.core.graphics.b.b(this.f3676x.i(), this.f3676x.k() + measuredHeight, this.f3676x.j(), this.f3676x.h())).a();
        } else {
            Rect rect = this.f3668p;
            rect.top += measuredHeight;
            rect.bottom = rect.bottom;
            this.f3676x = this.f3676x.l(0, measuredHeight, 0, 0);
        }
        q(this.f3656d, this.f3668p, true, true, true, true);
        if (!this.f3677y.equals(this.f3676x)) {
            C0271j0 c0271j0 = this.f3676x;
            this.f3677y = c0271j0;
            androidx.core.view.V.e(this.f3656d, c0271j0);
        }
        measureChildWithMargins(this.f3656d, i3, 0, i4, 0);
        e eVar2 = (e) this.f3656d.getLayoutParams();
        int iMax3 = Math.max(iMax, this.f3656d.getMeasuredWidth() + ((ViewGroup.MarginLayoutParams) eVar2).leftMargin + ((ViewGroup.MarginLayoutParams) eVar2).rightMargin);
        int iMax4 = Math.max(iMax2, this.f3656d.getMeasuredHeight() + ((ViewGroup.MarginLayoutParams) eVar2).topMargin + ((ViewGroup.MarginLayoutParams) eVar2).bottomMargin);
        int iCombineMeasuredStates2 = View.combineMeasuredStates(iCombineMeasuredStates, this.f3656d.getMeasuredState());
        setMeasuredDimension(View.resolveSizeAndState(Math.max(iMax3 + getPaddingLeft() + getPaddingRight(), getSuggestedMinimumWidth()), i3, iCombineMeasuredStates2), View.resolveSizeAndState(Math.max(iMax4 + getPaddingTop() + getPaddingBottom(), getSuggestedMinimumHeight()), i4, iCombineMeasuredStates2 << 16));
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean onNestedFling(View view, float f3, float f4, boolean z3) {
        if (!this.f3662j || !z3) {
            return false;
        }
        if (C(f4)) {
            p();
        } else {
            B();
        }
        this.f3663k = true;
        return true;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean onNestedPreFling(View view, float f3, float f4) {
        return false;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onNestedPreScroll(View view, int i3, int i4, int[] iArr) {
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onNestedScroll(View view, int i3, int i4, int i5, int i6) {
        int i7 = this.f3664l + i4;
        this.f3664l = i7;
        setActionBarHideOffset(i7);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onNestedScrollAccepted(View view, View view2, int i3) {
        this.f3652F.b(view, view2, i3);
        this.f3664l = getActionBarHideOffset();
        v();
        d dVar = this.f3678z;
        if (dVar != null) {
            dVar.b();
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean onStartNestedScroll(View view, View view2, int i3) {
        if ((i3 & 2) == 0 || this.f3657e.getVisibility() != 0) {
            return false;
        }
        return this.f3662j;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onStopNestedScroll(View view) {
        if (this.f3662j && !this.f3663k) {
            if (this.f3664l <= this.f3657e.getHeight()) {
                z();
            } else {
                y();
            }
        }
        d dVar = this.f3678z;
        if (dVar != null) {
            dVar.d();
        }
    }

    @Override // android.view.View
    public void onWindowSystemUiVisibilityChanged(int i3) {
        super.onWindowSystemUiVisibilityChanged(i3);
        A();
        int i4 = this.f3665m ^ i3;
        this.f3665m = i3;
        boolean z3 = (i3 & 4) == 0;
        boolean z4 = (i3 & 256) != 0;
        d dVar = this.f3678z;
        if (dVar != null) {
            dVar.e(!z4);
            if (z3 || !z4) {
                this.f3678z.a();
            } else {
                this.f3678z.f();
            }
        }
        if ((i4 & 256) == 0 || this.f3678z == null) {
            return;
        }
        androidx.core.view.V.U(this);
    }

    @Override // android.view.View
    protected void onWindowVisibilityChanged(int i3) {
        super.onWindowVisibilityChanged(i3);
        this.f3655c = i3;
        d dVar = this.f3678z;
        if (dVar != null) {
            dVar.c(i3);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.view.ViewGroup
    /* JADX INFO: renamed from: s, reason: merged with bridge method [inline-methods] */
    public e generateDefaultLayoutParams() {
        return new e(-1, -1);
    }

    public void setActionBarHideOffset(int i3) {
        v();
        this.f3657e.setTranslationY(-Math.max(0, Math.min(i3, this.f3657e.getHeight())));
    }

    public void setActionBarVisibilityCallback(d dVar) {
        this.f3678z = dVar;
        if (getWindowToken() != null) {
            this.f3678z.c(this.f3655c);
            int i3 = this.f3665m;
            if (i3 != 0) {
                onWindowSystemUiVisibilityChanged(i3);
                androidx.core.view.V.U(this);
            }
        }
    }

    public void setHasNonEmbeddedTabs(boolean z3) {
        this.f3661i = z3;
    }

    public void setHideOnContentScrollEnabled(boolean z3) {
        if (z3 != this.f3662j) {
            this.f3662j = z3;
            if (z3) {
                return;
            }
            v();
            setActionBarHideOffset(0);
        }
    }

    public void setIcon(int i3) {
        A();
        this.f3658f.setIcon(i3);
    }

    public void setLogo(int i3) {
        A();
        this.f3658f.p(i3);
    }

    public void setOverlayMode(boolean z3) {
        this.f3660h = z3;
    }

    public void setShowingForActionMode(boolean z3) {
    }

    public void setUiOptions(int i3) {
    }

    @Override // androidx.appcompat.widget.I
    public void setWindowCallback(Window.Callback callback) {
        A();
        this.f3658f.setWindowCallback(callback);
    }

    @Override // androidx.appcompat.widget.I
    public void setWindowTitle(CharSequence charSequence) {
        A();
        this.f3658f.setWindowTitle(charSequence);
    }

    @Override // android.view.ViewGroup
    public boolean shouldDelayChildPressedState() {
        return false;
    }

    @Override // android.view.ViewGroup
    /* JADX INFO: renamed from: t, reason: merged with bridge method [inline-methods] */
    public e generateLayoutParams(AttributeSet attributeSet) {
        return new e(getContext(), attributeSet);
    }

    void v() {
        removeCallbacks(this.f3650D);
        removeCallbacks(this.f3651E);
        ViewPropertyAnimator viewPropertyAnimator = this.f3648B;
        if (viewPropertyAnimator != null) {
            viewPropertyAnimator.cancel();
        }
    }

    public boolean x() {
        return this.f3660h;
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return new e(layoutParams);
    }

    public void setIcon(Drawable drawable) {
        A();
        this.f3658f.setIcon(drawable);
    }
}
