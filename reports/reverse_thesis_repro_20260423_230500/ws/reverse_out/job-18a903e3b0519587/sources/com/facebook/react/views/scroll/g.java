package com.facebook.react.views.scroll;

import Q1.p;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.OverScroller;
import android.widget.ScrollView;
import androidx.core.view.V;
import c1.AbstractC0339k;
import c2.C0353a;
import com.facebook.react.animated.NativeAnimatedModule;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.AbstractC0452j0;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.EnumC0446g0;
import com.facebook.react.uimanager.InterfaceC0450i0;
import com.facebook.react.uimanager.InterfaceC0458m0;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.uimanager.Z;
import com.facebook.react.views.scroll.b;
import com.facebook.react.views.scroll.j;
import java.lang.reflect.Field;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class g extends ScrollView implements InterfaceC0450i0, ViewGroup.OnHierarchyChangeListener, View.OnLayoutChangeListener, d, InterfaceC0458m0, j.c, j.e, j.a, j.b, j.d {

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private static Field f7939J = null;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private static boolean f7940K = false;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private int f7941A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private int f7942B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private A0 f7943C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final j.g f7944D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private final ValueAnimator f7945E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private EnumC0446g0 f7946F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private long f7947G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private int f7948H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private com.facebook.react.views.scroll.b f7949I;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final c f7950b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final OverScroller f7951c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final m f7952d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Rect f7953e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Rect f7954f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f7955g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Rect f7956h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private p f7957i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f7958j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f7959k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Runnable f7960l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f7961m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f7962n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f7963o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private String f7964p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Drawable f7965q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f7966r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f7967s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private int f7968t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private List f7969u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f7970v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f7971w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private int f7972x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private View f7973y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private ReadableMap f7974z;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f7975b = false;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f7976c = 0;

        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            NativeAnimatedModule nativeAnimatedModule;
            if (g.this.f7955g) {
                g.this.f7955g = false;
                this.f7976c = 0;
                V.T(g.this, this, 20L);
                return;
            }
            j.s(g.this);
            int i3 = this.f7976c + 1;
            this.f7976c = i3;
            if (i3 < 3) {
                if (g.this.f7959k && !this.f7975b) {
                    this.f7975b = true;
                    g.this.u(0);
                }
                V.T(g.this, this, 20L);
                return;
            }
            g.this.f7960l = null;
            if (g.this.f7963o) {
                j.j(g.this);
            }
            ReactContext reactContext = (ReactContext) g.this.getContext();
            if (reactContext != null && (nativeAnimatedModule = (NativeAnimatedModule) reactContext.getNativeModule(NativeAnimatedModule.class)) != null) {
                nativeAnimatedModule.userDrivenScrollEnded(g.this.getId());
            }
            g.this.r();
        }
    }

    static /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f7978a;

        static {
            int[] iArr = new int[p.values().length];
            f7978a = iArr;
            try {
                iArr[p.f2500d.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f7978a[p.f2501e.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f7978a[p.f2499c.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public g(Context context, com.facebook.react.views.scroll.a aVar) {
        super(context);
        this.f7950b = new c();
        this.f7952d = new m();
        this.f7953e = new Rect();
        this.f7954f = new Rect();
        this.f7957i = p.f2501e;
        this.f7959k = false;
        this.f7962n = true;
        this.f7966r = 0;
        this.f7967s = false;
        this.f7968t = 0;
        this.f7970v = true;
        this.f7971w = true;
        this.f7972x = 0;
        this.f7974z = null;
        this.f7941A = -1;
        this.f7942B = -1;
        this.f7943C = null;
        this.f7944D = new j.g();
        this.f7945E = ObjectAnimator.ofInt(this, "scrollY", 0, 0);
        this.f7946F = EnumC0446g0.f7609f;
        this.f7947G = 0L;
        this.f7948H = 0;
        this.f7949I = null;
        this.f7951c = getOverScrollerFromParent();
        setOnHierarchyChangeListener(this);
        setScrollBarStyle(33554432);
        setClipChildren(false);
        V.X(this, new h());
    }

    private boolean A() {
        View contentView = getContentView();
        return (contentView == null || contentView.getWidth() == 0 || contentView.getHeight() == 0) ? false : true;
    }

    private boolean B() {
        return false;
    }

    private int C(int i3) {
        if (getFlingAnimator() == this.f7945E) {
            return j.p(this, 0, i3, 0, getMaxScrollY()).y;
        }
        return v(i3) + j.m(this, getScrollY(), getReactScrollViewScrollState().b().y, i3);
    }

    private void D(int i3) {
        if (getFlingAnimator().isRunning()) {
            getFlingAnimator().cancel();
        }
        OverScroller overScroller = this.f7951c;
        if (overScroller == null || overScroller.isFinished()) {
            return;
        }
        int currY = this.f7951c.getCurrY();
        boolean zComputeScrollOffset = this.f7951c.computeScrollOffset();
        this.f7951c.forceFinished(true);
        if (!zComputeScrollOffset) {
            scrollTo(getScrollX(), i3 + (this.f7951c.getCurrX() - currY));
            return;
        }
        this.f7951c.fling(getScrollX(), i3, 0, (int) (this.f7951c.getCurrVelocity() * Math.signum(this.f7951c.getFinalY() - this.f7951c.getStartY())), 0, 0, 0, Integer.MAX_VALUE);
    }

    private void E(View view) {
        Rect rect = new Rect();
        view.getDrawingRect(rect);
        offsetDescendantRectToMyCoords(view, rect);
        int iComputeScrollDeltaToGetChildRectOnScreen = computeScrollDeltaToGetChildRectOnScreen(rect);
        if (iComputeScrollDeltaToGetChildRectOnScreen != 0) {
            scrollBy(0, iComputeScrollDeltaToGetChildRectOnScreen);
        }
    }

    private void G(int i3, int i4) {
        if (A()) {
            this.f7941A = -1;
            this.f7942B = -1;
        } else {
            this.f7941A = i3;
            this.f7942B = i4;
        }
    }

    private void H(int i3) {
        double snapInterval = getSnapInterval();
        double dM = j.m(this, getScrollY(), getReactScrollViewScrollState().b().y, i3);
        double dC = C(i3);
        double d3 = dM / snapInterval;
        int iFloor = (int) Math.floor(d3);
        int iCeil = (int) Math.ceil(d3);
        int iRound = (int) Math.round(d3);
        int iRound2 = (int) Math.round(dC / snapInterval);
        if (i3 > 0 && iCeil == iFloor) {
            iCeil++;
        } else if (i3 < 0 && iFloor == iCeil) {
            iFloor--;
        }
        if (i3 > 0 && iRound < iCeil && iRound2 > iFloor) {
            iRound = iCeil;
        } else if (i3 < 0 && iRound > iFloor && iRound2 < iCeil) {
            iRound = iFloor;
        }
        double d4 = ((double) iRound) * snapInterval;
        if (d4 != dM) {
            this.f7955g = true;
            f(getScrollX(), (int) d4);
        }
    }

    private void I(int i3) {
        getReactScrollViewScrollState().l(i3);
        j.k(this);
    }

    private View getContentView() {
        return getChildAt(0);
    }

    private int getMaxScrollY() {
        View view = this.f7973y;
        return Math.max(0, (view == null ? 0 : view.getHeight()) - ((getHeight() - getPaddingBottom()) - getPaddingTop()));
    }

    private OverScroller getOverScrollerFromParent() {
        if (!f7940K) {
            f7940K = true;
            try {
                Field declaredField = ScrollView.class.getDeclaredField("mScroller");
                f7939J = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException unused) {
                Y.a.I("ReactNative", "Failed to get mScroller field for ScrollView! This app will exhibit the bounce-back scrolling bug :(");
            }
        }
        Field field = f7939J;
        OverScroller overScroller = null;
        if (field != null) {
            try {
                Object obj = field.get(this);
                if (obj instanceof OverScroller) {
                    overScroller = (OverScroller) obj;
                } else {
                    Y.a.I("ReactNative", "Failed to cast mScroller field in ScrollView (probably due to OEM changes to AOSP)! This app will exhibit the bounce-back scrolling bug :(");
                }
            } catch (IllegalAccessException e3) {
                throw new RuntimeException("Failed to get mScroller from ScrollView!", e3);
            }
        }
        return overScroller;
    }

    private int getSnapInterval() {
        int i3 = this.f7968t;
        return i3 != 0 ? i3 : getHeight();
    }

    private void p() {
        Runnable runnable = this.f7960l;
        if (runnable != null) {
            removeCallbacks(runnable);
            this.f7960l = null;
            getFlingAnimator().cancel();
        }
    }

    private int q(int i3) {
        if (Build.VERSION.SDK_INT != 28) {
            return i3;
        }
        float fSignum = Math.signum(this.f7950b.b());
        if (fSignum == 0.0f) {
            fSignum = Math.signum(i3);
        }
        return (int) (Math.abs(i3) * fSignum);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void r() {
        if (B()) {
            Z0.a.c(null);
            Z0.a.c(this.f7964p);
            throw null;
        }
    }

    private void s() {
        if (B()) {
            Z0.a.c(null);
            Z0.a.c(this.f7964p);
            throw null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0188  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void u(int r28) {
        /*
            Method dump skipped, instruction units count: 510
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.scroll.g.u(int):void");
    }

    private int w(int i3, int i4, int i5, int i6) {
        int i7;
        if (i3 == 1) {
            return i4;
        }
        if (i3 == 2) {
            i7 = (i6 - i5) / 2;
        } else {
            if (i3 != 3) {
                throw new IllegalStateException("Invalid SnapToAlignment value: " + this.f7972x);
            }
            i7 = i6 - i5;
        }
        return i4 - i7;
    }

    private int x(View view) {
        view.getDrawingRect(this.f7953e);
        offsetDescendantRectToMyCoords(view, this.f7953e);
        return computeScrollDeltaToGetChildRectOnScreen(this.f7953e);
    }

    private void z(int i3, int i4) {
        if (this.f7960l != null) {
            return;
        }
        if (this.f7963o) {
            s();
            j.i(this, i3, i4);
        }
        this.f7955g = false;
        a aVar = new a();
        this.f7960l = aVar;
        V.T(this, aVar, 20L);
    }

    public void F(float f3, int i3) {
        C0433a.q(this, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(C0444f0.f(f3), X.f7535b));
    }

    @Override // com.facebook.react.views.scroll.j.a
    public void a(int i3, int i4) {
        this.f7945E.cancel();
        int iL = j.l(getContext());
        this.f7945E.setDuration(iL).setIntValues(i3, i4);
        this.f7945E.start();
        if (this.f7963o) {
            j.i(this, 0, iL > 0 ? (i4 - i3) / iL : 0);
            j.a(this);
        }
    }

    @Override // com.facebook.react.views.scroll.j.d
    public void b(int i3, int i4) {
        scrollTo(i3, i4);
        D(i4);
    }

    @Override // com.facebook.react.views.scroll.d
    public boolean c(View view) {
        int iX = x(view);
        view.getDrawingRect(this.f7953e);
        return iX != 0 && Math.abs(iX) < this.f7953e.width();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0458m0
    public void d(int i3, int i4, int i5, int i6) {
        this.f7954f.set(i3, i4, i5, i6);
    }

    @Override // android.view.View
    public boolean dispatchGenericMotionEvent(MotionEvent motionEvent) {
        if (EnumC0446g0.c(this.f7946F)) {
            return super.dispatchGenericMotionEvent(motionEvent);
        }
        return false;
    }

    @Override // android.widget.ScrollView, android.view.View
    public void draw(Canvas canvas) {
        if (this.f7966r != 0) {
            View contentView = getContentView();
            if (this.f7965q != null && contentView != null && contentView.getBottom() < getHeight()) {
                this.f7965q.setBounds(0, contentView.getBottom(), getWidth(), getHeight());
                this.f7965q.draw(canvas);
            }
        }
        super.draw(canvas);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0450i0
    public void e() {
        if (this.f7961m) {
            C0353a.c(0L, "ReactScrollView.updateClippingRect");
            try {
                Z0.a.c(this.f7956h);
                AbstractC0452j0.a(this, this.f7956h);
                KeyEvent.Callback contentView = getContentView();
                if (contentView instanceof InterfaceC0450i0) {
                    ((InterfaceC0450i0) contentView).e();
                }
            } finally {
                C0353a.i(0L);
            }
        }
    }

    @Override // android.widget.ScrollView
    public boolean executeKeyEvent(KeyEvent keyEvent) {
        int keyCode = keyEvent.getKeyCode();
        if (this.f7962n || !(keyCode == 19 || keyCode == 20)) {
            return super.executeKeyEvent(keyEvent);
        }
        return false;
    }

    @Override // com.facebook.react.views.scroll.j.d
    public void f(int i3, int i4) {
        j.r(this, i3, i4);
        G(i3, i4);
    }

    @Override // android.widget.ScrollView
    public void fling(int i3) {
        int iQ = q(i3);
        if (this.f7959k) {
            u(iQ);
        } else if (this.f7951c != null) {
            this.f7951c.fling(getScrollX(), getScrollY(), 0, iQ, 0, 0, 0, Integer.MAX_VALUE, 0, ((getHeight() - getPaddingBottom()) - getPaddingTop()) / 2);
            V.R(this);
        } else {
            super.fling(iQ);
        }
        z(0, iQ);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0450i0
    public void g(Rect rect) {
        rect.set((Rect) Z0.a.c(this.f7956h));
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean getChildVisibleRect(View view, Rect rect, Point point) {
        return super.getChildVisibleRect(view, rect, point);
    }

    @Override // com.facebook.react.views.scroll.j.a
    public ValueAnimator getFlingAnimator() {
        return this.f7945E;
    }

    @Override // com.facebook.react.views.scroll.j.b
    public long getLastScrollDispatchTime() {
        return this.f7947G;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0456l0
    public String getOverflow() {
        int i3 = b.f7978a[this.f7957i.ordinal()];
        if (i3 == 1) {
            return "hidden";
        }
        if (i3 == 2) {
            return "scroll";
        }
        if (i3 != 3) {
            return null;
        }
        return "visible";
    }

    @Override // com.facebook.react.uimanager.InterfaceC0458m0
    public Rect getOverflowInset() {
        return this.f7954f;
    }

    public EnumC0446g0 getPointerEvents() {
        return this.f7946F;
    }

    @Override // com.facebook.react.views.scroll.j.c
    public j.g getReactScrollViewScrollState() {
        return this.f7944D;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0450i0
    public boolean getRemoveClippedSubviews() {
        return this.f7961m;
    }

    @Override // com.facebook.react.views.scroll.d
    public boolean getScrollEnabled() {
        return this.f7962n;
    }

    @Override // com.facebook.react.views.scroll.j.b
    public int getScrollEventThrottle() {
        return this.f7948H;
    }

    @Override // com.facebook.react.views.scroll.j.e
    public A0 getStateWrapper() {
        return this.f7943C;
    }

    public void o() {
        OverScroller overScroller = this.f7951c;
        if (overScroller == null || overScroller.isFinished()) {
            return;
        }
        this.f7951c.abortAnimation();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.f7961m) {
            e();
        }
        com.facebook.react.views.scroll.b bVar = this.f7949I;
        if (bVar != null) {
            bVar.f();
        }
    }

    @Override // android.view.ViewGroup.OnHierarchyChangeListener
    public void onChildViewAdded(View view, View view2) {
        this.f7973y = view2;
        view2.addOnLayoutChangeListener(this);
    }

    @Override // android.view.ViewGroup.OnHierarchyChangeListener
    public void onChildViewRemoved(View view, View view2) {
        View view3 = this.f7973y;
        if (view3 != null) {
            view3.removeOnLayoutChangeListener(this);
            this.f7973y = null;
        }
    }

    @Override // android.widget.ScrollView, android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        com.facebook.react.views.scroll.b bVar = this.f7949I;
        if (bVar != null) {
            bVar.g();
        }
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        if (this.f7957i != p.f2499c) {
            C0433a.a(this, canvas);
        }
        super.onDraw(canvas);
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        String str = (String) getTag(AbstractC0339k.f5596t);
        if (str != null) {
            accessibilityNodeInfo.setViewIdResourceName(str);
        }
    }

    @Override // android.widget.ScrollView, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (!this.f7962n) {
            return false;
        }
        if (!EnumC0446g0.c(this.f7946F)) {
            return true;
        }
        try {
            if (super.onInterceptTouchEvent(motionEvent)) {
                y(motionEvent);
                return true;
            }
        } catch (IllegalArgumentException e3) {
            Y.a.J("ReactNative", "Error intercepting touch event.", e3);
        }
        return false;
    }

    @Override // android.widget.ScrollView, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        if (A()) {
            int scrollX = this.f7941A;
            if (scrollX == -1) {
                scrollX = getScrollX();
            }
            int scrollY = this.f7942B;
            if (scrollY == -1) {
                scrollY = getScrollY();
            }
            scrollTo(scrollX, scrollY);
        }
        j.c(this);
    }

    @Override // android.view.View.OnLayoutChangeListener
    public void onLayoutChange(View view, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        if (this.f7973y == null) {
            return;
        }
        com.facebook.react.views.scroll.b bVar = this.f7949I;
        if (bVar != null) {
            bVar.h();
        }
        if (isShown() && A()) {
            int scrollY = getScrollY();
            int maxScrollY = getMaxScrollY();
            if (scrollY > maxScrollY) {
                scrollTo(getScrollX(), maxScrollY);
            }
        }
        j.b(this);
    }

    @Override // android.widget.ScrollView, android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i3, int i4) {
        Z.a(i3, i4);
        setMeasuredDimension(View.MeasureSpec.getSize(i3), View.MeasureSpec.getSize(i4));
    }

    @Override // android.widget.ScrollView, android.view.View
    protected void onOverScrolled(int i3, int i4, boolean z3, boolean z4) {
        int maxScrollY;
        OverScroller overScroller = this.f7951c;
        if (overScroller != null && this.f7973y != null && !overScroller.isFinished() && this.f7951c.getCurrY() != this.f7951c.getFinalY() && i4 >= (maxScrollY = getMaxScrollY())) {
            this.f7951c.abortAnimation();
            i4 = maxScrollY;
        }
        super.onOverScrolled(i3, i4, z3, z4);
    }

    @Override // android.view.View
    protected void onScrollChanged(int i3, int i4, int i5, int i6) {
        C0353a.c(0L, "ReactScrollView.onScrollChanged");
        try {
            super.onScrollChanged(i3, i4, i5, i6);
            this.f7955g = true;
            if (this.f7950b.c(i3, i4)) {
                if (this.f7961m) {
                    e();
                }
                j.u(this, this.f7950b.a(), this.f7950b.b());
            }
            C0353a.i(0L);
        } catch (Throwable th) {
            C0353a.i(0L);
            throw th;
        }
    }

    @Override // android.widget.ScrollView, android.view.View
    protected void onSizeChanged(int i3, int i4, int i5, int i6) {
        super.onSizeChanged(i3, i4, i5, i6);
        if (this.f7961m) {
            e();
        }
    }

    @Override // android.widget.ScrollView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (!this.f7962n || !EnumC0446g0.b(this.f7946F)) {
            return false;
        }
        this.f7952d.a(motionEvent);
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 1 && this.f7958j) {
            j.s(this);
            float fB = this.f7952d.b();
            float fC = this.f7952d.c();
            j.e(this, fB, fC);
            O1.m.a(this, motionEvent);
            this.f7958j = false;
            z(Math.round(fB), Math.round(fC));
        }
        if (actionMasked == 0) {
            p();
        }
        return super.onTouchEvent(motionEvent);
    }

    @Override // android.widget.ScrollView, android.view.ViewGroup, android.view.ViewParent
    public void requestChildFocus(View view, View view2) {
        if (view2 != null) {
            E(view2);
        }
        super.requestChildFocus(view, view2);
    }

    @Override // android.widget.ScrollView, android.view.View
    public void scrollTo(int i3, int i4) {
        super.scrollTo(i3, i4);
        j.s(this);
        G(i3, i4);
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        C0433a.n(this, Integer.valueOf(i3));
    }

    public void setBorderRadius(float f3) {
        F(f3, Q1.d.f2402b.ordinal());
    }

    public void setBorderStyle(String str) {
        C0433a.r(this, str == null ? null : Q1.f.b(str));
    }

    public void setContentOffset(ReadableMap readableMap) {
        ReadableMap readableMap2 = this.f7974z;
        if (readableMap2 == null || !readableMap2.equals(readableMap)) {
            this.f7974z = readableMap;
            if (readableMap != null) {
                scrollTo((int) C0444f0.g(readableMap.hasKey("x") ? readableMap.getDouble("x") : 0.0d), (int) C0444f0.g(readableMap.hasKey("y") ? readableMap.getDouble("y") : 0.0d));
            } else {
                scrollTo(0, 0);
            }
        }
    }

    public void setDecelerationRate(float f3) {
        getReactScrollViewScrollState().h(f3);
        OverScroller overScroller = this.f7951c;
        if (overScroller != null) {
            overScroller.setFriction(1.0f - f3);
        }
    }

    public void setDisableIntervalMomentum(boolean z3) {
        this.f7967s = z3;
    }

    public void setEndFillColor(int i3) {
        if (i3 != this.f7966r) {
            this.f7966r = i3;
            this.f7965q = new ColorDrawable(this.f7966r);
        }
    }

    @Override // com.facebook.react.views.scroll.j.b
    public void setLastScrollDispatchTime(long j3) {
        this.f7947G = j3;
    }

    public void setMaintainVisibleContentPosition(b.C0118b c0118b) {
        com.facebook.react.views.scroll.b bVar;
        if (c0118b != null && this.f7949I == null) {
            com.facebook.react.views.scroll.b bVar2 = new com.facebook.react.views.scroll.b(this, false);
            this.f7949I = bVar2;
            bVar2.f();
        } else if (c0118b == null && (bVar = this.f7949I) != null) {
            bVar.g();
            this.f7949I = null;
        }
        com.facebook.react.views.scroll.b bVar3 = this.f7949I;
        if (bVar3 != null) {
            bVar3.e(c0118b);
        }
    }

    public void setOverflow(String str) {
        if (str == null) {
            this.f7957i = p.f2501e;
        } else {
            p pVarB = p.b(str);
            if (pVarB == null) {
                pVarB = p.f2501e;
            }
            this.f7957i = pVarB;
        }
        invalidate();
    }

    public void setPagingEnabled(boolean z3) {
        this.f7959k = z3;
    }

    public void setPointerEvents(EnumC0446g0 enumC0446g0) {
        this.f7946F = enumC0446g0;
    }

    public void setRemoveClippedSubviews(boolean z3) {
        if (z3 && this.f7956h == null) {
            this.f7956h = new Rect();
        }
        this.f7961m = z3;
        e();
    }

    public void setScrollAwayTopPaddingEnabledUnstable(int i3) {
        int childCount = getChildCount();
        Z0.a.b(childCount <= 1, "React Native ScrollView should not have more than one child, it should have exactly 1 child; a content View");
        if (childCount > 0) {
            for (int i4 = 0; i4 < childCount; i4++) {
                getChildAt(i4).setTranslationY(i3);
            }
            setPadding(0, 0, 0, i3);
        }
        I(i3);
        setRemoveClippedSubviews(this.f7961m);
    }

    public void setScrollEnabled(boolean z3) {
        this.f7962n = z3;
    }

    public void setScrollEventThrottle(int i3) {
        this.f7948H = i3;
    }

    public void setScrollPerfTag(String str) {
        this.f7964p = str;
    }

    public void setSendMomentumEvents(boolean z3) {
        this.f7963o = z3;
    }

    public void setSnapInterval(int i3) {
        this.f7968t = i3;
    }

    public void setSnapOffsets(List<Integer> list) {
        this.f7969u = list;
    }

    public void setSnapToAlignment(int i3) {
        this.f7972x = i3;
    }

    public void setSnapToEnd(boolean z3) {
        this.f7971w = z3;
    }

    public void setSnapToStart(boolean z3) {
        this.f7970v = z3;
    }

    public void setStateWrapper(A0 a02) {
        this.f7943C = a02;
    }

    public void t() {
        awakenScrollBars();
    }

    public int v(int i3) {
        return j.p(this, 0, i3, 0, getMaxScrollY()).y;
    }

    protected void y(MotionEvent motionEvent) {
        O1.m.b(this, motionEvent);
        j.d(this);
        this.f7958j = true;
        s();
        getFlingAnimator().cancel();
    }
}
